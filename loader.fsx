open System
open System.Buffers.Binary
open System.IO
open System.Net.Http
open System.Numerics
open System.Runtime.InteropServices
open System.Security.Cryptography
open System.Security.Principal
open System.Text
open System.Threading
open System.Threading.Tasks
open System.Drawing
open System.Windows.Forms
open Microsoft.Win32.SafeHandles

module LoaderState =
    type State =
        | Idle
        | DiscoveringTarget
        | DownloadingPayload
        | VerifyingPayload
        | PreparingIpc
        | InitializingPayload
        | WaitingForReady
        | Running
        | Stopping
        | Stopped
        | Failed of string

    let describe = function
        | Idle -> "Idle"
        | DiscoveringTarget -> "Discovering target"
        | DownloadingPayload -> "Downloading payload"
        | VerifyingPayload -> "Verifying payload"
        | PreparingIpc -> "Preparing IPC"
        | InitializingPayload -> "Initializing payload"
        | WaitingForReady -> "Waiting for ready"
        | Running -> "Running"
        | Stopping -> "Stopping"
        | Stopped -> "Stopped"
        | Failed message -> $"Failed: {message}"

    type Controller() =
        let gate = obj()
        let mutable state = Idle

        let canTransition current next =
            match current, next with
            | Idle, (DiscoveringTarget | DownloadingPayload | PreparingIpc | Stopped | Failed _) -> true
            | DiscoveringTarget, (Idle | Failed _) -> true
            | DownloadingPayload, (VerifyingPayload | Idle | Failed _) -> true
            | VerifyingPayload, (PreparingIpc | Idle | Failed _) -> true
            | PreparingIpc, (WaitingForReady | Idle | Failed _) -> true
            | WaitingForReady, (Running | Stopping | Idle | Failed _) -> true
            | Running, (Stopping | Failed _) -> true
            | Failed _, (Idle | DiscoveringTarget | DownloadingPayload | Stopping | Stopped) -> true
            | Stopping, (Stopped | Failed _) -> true
            | Stopped, Idle -> true
            | _ -> false

        member _.State = lock gate (fun () -> state)

        member _.TryTransition(next) =
            lock gate (fun () ->
                if canTransition state next then
                    state <- next
                    true
                else
                    false)

        member _.Transition(next) =
            lock gate (fun () ->
                if not (canTransition state next) then
                    invalidOp $"Invalid loader transition: {describe state} -> {describe next}"
                state <- next)

module Configuration =
    [<Literal>]
    let Version = 3u

    [<Literal>]
    let MaximumWhitelistEntries = 8

    [<Literal>]
    let MaximumWhitelistBytes = 31

    type RandomizationMode =
        | Normal = 0
        | Extra = 1
        | ExtraPlus = 2

    type ClickerConfig = {
        Enabled: bool
        MinimumCps: int
        MaximumCps: int
        Randomization: RandomizationMode
        HoldToClick: bool
    }

    type Config = {
        Version: uint32
        Left: ClickerConfig
        LeftTriggerMode: bool
        LeftBreakBlocks: bool
        LeftBreakDelayMinimum: int
        LeftBreakDelayMaximum: int
        LeftBreakWhitelist: bool
        Right: ClickerConfig
        RightStartDelayMillis: int
        RightUseItemWhitelist: bool
        RightWhitelist: string list
        HitFlickEnabled: bool
    }

    let defaults = {
        Version = Version
        Left = {
            Enabled = true
            MinimumCps = 13
            MaximumCps = 18
            Randomization = RandomizationMode.ExtraPlus
            HoldToClick = true
        }
        LeftTriggerMode = false
        LeftBreakBlocks = true
        LeftBreakDelayMinimum = 0
        LeftBreakDelayMaximum = 10
        LeftBreakWhitelist = false
        Right = {
            Enabled = true
            MinimumCps = 14
            MaximumCps = 18
            Randomization = RandomizationMode.Extra
            HoldToClick = true
        }
        RightStartDelayMillis = 200
        RightUseItemWhitelist = true
        RightWhitelist = [ "blocks" ]
        HitFlickEnabled = false
    }

    let private validateClicker name config = [
        if config.MinimumCps < 1 || config.MinimumCps > 20 then
            $"{name} minimum CPS must be between 1 and 20"
        if config.MaximumCps < 1 || config.MaximumCps > 20 then
            $"{name} maximum CPS must be between 1 and 20"
        if config.MinimumCps > config.MaximumCps then
            $"{name} minimum CPS cannot exceed maximum CPS"
        if not (Enum.IsDefined(typeof<RandomizationMode>, config.Randomization)) then
            $"{name} randomization mode is invalid"
    ]

    let validate config = [
        if config.Version <> Version then
            $"Configuration version must be {Version}"
        yield! validateClicker "Left" config.Left
        if config.LeftBreakDelayMinimum < 0 || config.LeftBreakDelayMinimum > 2000 then
            "Left break minimum delay must be between 0 and 2000 ms"
        if config.LeftBreakDelayMaximum < 0 || config.LeftBreakDelayMaximum > 2000 then
            "Left break maximum delay must be between 0 and 2000 ms"
        if config.LeftBreakDelayMinimum > config.LeftBreakDelayMaximum then
            "Left break minimum delay cannot exceed maximum delay"
        yield! validateClicker "Right" config.Right
        if config.RightStartDelayMillis < 0 || config.RightStartDelayMillis > 1000 then
            "Right start delay must be between 0 and 1000 ms"
        if config.RightWhitelist.Length > MaximumWhitelistEntries then
            $"Right whitelist cannot contain more than {MaximumWhitelistEntries} entries"
        for item in config.RightWhitelist do
            if String.IsNullOrWhiteSpace(item) then
                "Whitelist entries cannot be empty"
            if item.IndexOf('\000') >= 0 then
                "Whitelist entries cannot contain embedded terminators"
            if Text.Encoding.UTF8.GetByteCount(item) > MaximumWhitelistBytes then
                $"Whitelist entries cannot exceed {MaximumWhitelistBytes} UTF-8 bytes"
    ]

module Pe =
    [<Literal>]
    let private DosSignature = 0x5A4Dus

    [<Literal>]
    let private NtSignature = 0x00004550u

    [<Literal>]
    let private Amd64Machine = 0x8664us

    [<Literal>]
    let private Pe32PlusMagic = 0x020Bus

    [<Literal>]
    let private SectionHeaderSize = 40

    type Section = {
        Name: string
        VirtualAddress: uint32
        VirtualSize: uint32
        RawOffset: uint32
        RawSize: uint32
    }

    type Image = {
        ImageBase: uint64
        SizeOfImage: uint32
        SizeOfHeaders: uint32
        EntryPointRva: uint32
        Sections: Section list
    }

    let private fail message = raise (InvalidDataException(message))

    let private ensureRange (bytes: byte array) offset length description =
        if offset < 0 || length < 0 || offset > bytes.Length - length then
            fail $"{description} is outside the payload"

    let private u16 bytes offset description =
        ensureRange bytes offset 2 description
        BinaryPrimitives.ReadUInt16LittleEndian(ReadOnlySpan(bytes, offset, 2))

    let private u32 bytes offset description =
        ensureRange bytes offset 4 description
        BinaryPrimitives.ReadUInt32LittleEndian(ReadOnlySpan(bytes, offset, 4))

    let private u64 bytes offset description =
        ensureRange bytes offset 8 description
        BinaryPrimitives.ReadUInt64LittleEndian(ReadOnlySpan(bytes, offset, 8))

    let private checkedInt value description =
        if value > uint32 Int32.MaxValue then fail $"{description} is too large"
        int value

    let private checkedAdd left right description =
        let result = uint64 left + uint64 right
        if result > uint64 UInt32.MaxValue then fail $"{description} overflows"
        uint32 result

    let inspect (bytes: byte array) =
        if isNull bytes then nullArg "bytes"
        ensureRange bytes 0 64 "DOS header"
        if u16 bytes 0 "DOS signature" <> DosSignature then fail "Invalid DOS signature"

        let ntOffset = checkedInt (u32 bytes 0x3C "NT header offset") "NT header offset"
        ensureRange bytes ntOffset 24 "NT and COFF headers"
        if u32 bytes ntOffset "NT signature" <> NtSignature then fail "Invalid NT signature"
        if u16 bytes (ntOffset + 4) "machine type" <> Amd64Machine then
            fail "Payload is not AMD64"

        let sectionCount = int (u16 bytes (ntOffset + 6) "section count")
        if sectionCount < 1 || sectionCount > 96 then fail "Section count is unreasonable"
        let optionalSize = int (u16 bytes (ntOffset + 20) "optional header size")
        if optionalSize < 112 then fail "PE32+ optional header is truncated"

        let optionalOffset = ntOffset + 24
        ensureRange bytes optionalOffset optionalSize "optional header"
        if u16 bytes optionalOffset "optional header magic" <> Pe32PlusMagic then
            fail "Payload is not PE32+"

        let entryPoint = u32 bytes (optionalOffset + 16) "entry point"
        let imageBase = u64 bytes (optionalOffset + 24) "image base"
        let sizeOfImage = u32 bytes (optionalOffset + 56) "image size"
        let sizeOfHeaders = u32 bytes (optionalOffset + 60) "header size"
        let directoryCount = u32 bytes (optionalOffset + 108) "data directory count"
        if sizeOfImage = 0u then fail "Image size cannot be zero"
        if entryPoint >= sizeOfImage then fail "Entry point is outside the image"
        if sizeOfHeaders = 0u || uint64 sizeOfHeaders > uint64 bytes.Length then
            fail "Header size is outside the payload"
        if directoryCount > 16u then fail "Data directory count exceeds PE32+ limits"
        let directoryBytes = int directoryCount * 8
        if 112 + directoryBytes > optionalSize then fail "Data directories are truncated"
        for index in 0 .. int directoryCount - 1 do
            let offset = optionalOffset + 112 + index * 8
            let rva = u32 bytes offset $"data directory {index} RVA"
            let size = u32 bytes (offset + 4) $"data directory {index} size"
            if rva = 0u && size <> 0u then fail $"Data directory {index} has size without an RVA"
            if index = 4 && rva <> 0u then
                let certificateEnd = uint64 rva + uint64 size
                if certificateEnd > uint64 bytes.Length then
                    fail "Certificate directory exceeds the payload"
            elif rva <> 0u && checkedAdd rva size $"data directory {index} range" > sizeOfImage then
                fail $"Data directory {index} exceeds the image"

        let sectionTableOffset = optionalOffset + optionalSize
        let sectionTableSize = sectionCount * SectionHeaderSize
        ensureRange bytes sectionTableOffset sectionTableSize "section table"
        let sections = [
            for index in 0 .. sectionCount - 1 do
                let offset = sectionTableOffset + index * SectionHeaderSize
                let rawName = bytes[offset .. offset + 7]
                let nameLength = rawName |> Array.tryFindIndex ((=) 0uy) |> Option.defaultValue 8
                let name = Text.Encoding.ASCII.GetString(rawName, 0, nameLength)
                let virtualSize = u32 bytes (offset + 8) $"section {index} virtual size"
                let virtualAddress = u32 bytes (offset + 12) $"section {index} virtual address"
                let rawSize = u32 bytes (offset + 16) $"section {index} raw size"
                let rawOffset = u32 bytes (offset + 20) $"section {index} raw offset"
                let mappedSize = max virtualSize rawSize
                let virtualEnd = checkedAdd virtualAddress mappedSize $"section {index} virtual range"
                if virtualEnd > sizeOfImage then fail $"Section {index} exceeds the image"
                if rawSize > 0u then
                    let rawEnd = uint64 rawOffset + uint64 rawSize
                    if rawEnd > uint64 bytes.Length then fail $"Section {index} raw data exceeds the payload"
                yield {
                    Name = name
                    VirtualAddress = virtualAddress
                    VirtualSize = virtualSize
                    RawOffset = rawOffset
                    RawSize = rawSize
                }
        ]

        {
            ImageBase = imageBase
            SizeOfImage = sizeOfImage
            SizeOfHeaders = sizeOfHeaders
            EntryPointRva = entryPoint
            Sections = sections
        }

module PeMappingSimulator =
    [<Literal>]
    let private DosSignature = 0x5A4Dus

    [<Literal>]
    let private NtSignature = 0x00004550u

    [<Literal>]
    let private Pe32PlusMagic = 0x020Bus

    [<Literal>]
    let private ImageScnMemDiscardable = 0x02000000u

    [<Literal>]
    let private ImageScnMemExecute = 0x20000000u

    [<Literal>]
    let private ImageScnMemRead = 0x40000000u

    [<Literal>]
    let private ImageScnMemWrite = 0x80000000u

    type Section = {
        Name: string
        VirtualAddress: uint32
        VirtualSize: uint32
        PointerToRawData: uint32
        SizeOfRawData: uint32
        Characteristics: uint32
    }

    type RelocationBlock = {
        PageRVA: uint32
        // Each entry is the raw PE base-relocation WORD: type in bits 15..12,
        // offset within PageRVA in bits 11..0.
        Entries: uint16 array
    }

    type ImportDescriptor = {
        NameRVA: uint32
        OriginalFirstThunkRVA: uint32
        FirstThunkRVA: uint32
    }

    type PEImage = {
        ImageBase: uint64
        SizeOfImage: uint32
        EntryPointRVA: uint32
        Sections: Section array
        Relocations: RelocationBlock array
        Imports: ImportDescriptor array
    }

    type UnresolvedImport = {
        Dll: string
        Name: string option
        Ordinal: uint16 option
        Hint: uint16 option
    }

    type PageProtection =
        | NoAccess
        | ReadOnly
        | ReadWrite
        | Execute
        | ExecuteRead
        | ExecuteReadWrite

    type SectionProtection = {
        Name: string
        RVA: uint32
        Size: uint32
        Protection: PageProtection
        Discardable: bool
    }

    let private invalid message = raise (InvalidDataException(message))

    let private asResult action =
        try Ok(action ()) with
        | :? InvalidDataException as error -> Error error.Message
        | :? ArgumentException as error -> Error error.Message
        | :? OverflowException as error -> Error error.Message

    let private requireArray name (value: 'T array) =
        if isNull value then invalid $"{name} cannot be null"

    let private checkedInt (value: uint32) description =
        if value > uint32 Int32.MaxValue then invalid $"{description} is too large"
        int value

    let private checkedRvaEnd rva size description =
        let finish = uint64 rva + uint64 size
        if finish > uint64 UInt32.MaxValue then invalid $"{description} overflows the RVA space"
        uint32 finish

    let private ensureRange (bytes: byte array) offset length description =
        if isNull bytes then invalid "Byte buffer cannot be null"
        if offset < 0 || length < 0 || offset > bytes.Length - length then
            invalid $"{description} is outside the byte buffer"

    let private ensureRvaRange (bytes: byte array) rva length description =
        let offset = checkedInt rva description
        let count = checkedInt length description
        ensureRange bytes offset count description
        offset, count

    let private readU16 bytes offset description =
        ensureRange bytes offset 2 description
        BinaryPrimitives.ReadUInt16LittleEndian(ReadOnlySpan<byte>(bytes, offset, 2))

    let private readU32 bytes offset description =
        ensureRange bytes offset 4 description
        BinaryPrimitives.ReadUInt32LittleEndian(ReadOnlySpan<byte>(bytes, offset, 4))

    let private readU64 bytes offset description =
        ensureRange bytes offset 8 description
        BinaryPrimitives.ReadUInt64LittleEndian(ReadOnlySpan<byte>(bytes, offset, 8))

    let private sizeOfHeaders (fileBytes: byte array) =
        ensureRange fileBytes 0 64 "DOS header"
        if readU16 fileBytes 0 "DOS signature" <> DosSignature then invalid "Invalid DOS signature"
        let ntOffset = readU32 fileBytes 0x3C "NT header offset" |> fun value -> checkedInt value "NT header offset"
        ensureRange fileBytes ntOffset 24 "NT and COFF headers"
        if readU32 fileBytes ntOffset "NT signature" <> NtSignature then invalid "Invalid NT signature"
        let optionalSize = int (readU16 fileBytes (ntOffset + 20) "optional header size")
        let optionalOffset = ntOffset + 24
        ensureRange fileBytes optionalOffset optionalSize "optional header"
        if optionalSize < 64 then invalid "Optional header is too small"
        if readU16 fileBytes optionalOffset "optional header magic" <> Pe32PlusMagic then
            invalid "Only PE32+ images are supported"
        readU32 fileBytes (optionalOffset + 60) "SizeOfHeaders"

    let private validateImage image =
        if obj.ReferenceEquals(image, null) then invalid "PE image cannot be null"
        if image.SizeOfImage = 0u then invalid "SizeOfImage cannot be zero"
        checkedInt image.SizeOfImage "SizeOfImage" |> ignore
        if image.EntryPointRVA >= image.SizeOfImage then invalid "Entry point is outside the image"
        requireArray "Sections" image.Sections
        requireArray "Relocations" image.Relocations
        requireArray "Imports" image.Imports
        for index, section in image.Sections |> Array.indexed do
            let mappedSize = max section.VirtualSize section.SizeOfRawData
            let finish = checkedRvaEnd section.VirtualAddress mappedSize $"Section {index} virtual range"
            if finish > image.SizeOfImage then invalid $"Section {index} exceeds SizeOfImage"

    /// Converts an RVA backed by headers or section raw data to its file offset.
    let rvaToFileOffset (fileBytes: byte array) (image: PEImage) rva = asResult (fun () ->
        validateImage image
        let headersSize = sizeOfHeaders fileBytes
        if rva < headersSize then
            let offset = checkedInt rva "Header RVA"
            ensureRange fileBytes offset 1 "Header RVA"
            offset
        else
            let candidates =
                image.Sections
                |> Array.filter (fun section ->
                    let mappedSize = max section.VirtualSize section.SizeOfRawData
                    uint64 rva >= uint64 section.VirtualAddress &&
                    uint64 rva < uint64 section.VirtualAddress + uint64 mappedSize)
            if candidates.Length <> 1 then
                invalid $"RVA 0x{rva:X8} does not identify exactly one section"
            let section = candidates[0]
            let relative = rva - section.VirtualAddress
            if relative >= section.SizeOfRawData then
                invalid $"RVA 0x{rva:X8} refers to zero-filled section data and has no file offset"
            let fileOffset = uint64 section.PointerToRawData + uint64 relative
            if fileOffset > uint64 Int32.MaxValue then invalid "File offset is too large"
            let offset = int fileOffset
            ensureRange fileBytes offset 1 $"RVA 0x{rva:X8}"
            offset)

    let mapHeadersAndSections (fileBytes: byte array) (image: PEImage) = asResult (fun () ->
        validateImage image
        let headersSize = sizeOfHeaders fileBytes
        if headersSize = 0u || headersSize > image.SizeOfImage then
            invalid "SizeOfHeaders is zero or exceeds SizeOfImage"
        let headerCount = checkedInt headersSize "SizeOfHeaders"
        ensureRange fileBytes 0 headerCount "PE headers"

        let ranges = ResizeArray<uint32 * uint32 * string>()
        ranges.Add(0u, headersSize, "PE headers")
        for index, section in image.Sections |> Array.indexed do
            let mappedSize = max section.VirtualSize section.SizeOfRawData
            if mappedSize > 0u then
                let finish = checkedRvaEnd section.VirtualAddress mappedSize $"Section {index} virtual range"
                if finish > image.SizeOfImage then invalid $"Section {index} exceeds SizeOfImage"
                for start, existingEnd, existingName in ranges do
                    if section.VirtualAddress < existingEnd && start < finish then
                        invalid $"Section {index} overlaps {existingName}"
                ranges.Add(section.VirtualAddress, finish, $"section {index}")
            if section.SizeOfRawData > 0u then
                let rawOffset = checkedInt section.PointerToRawData $"Section {index} raw offset"
                let rawCount = checkedInt section.SizeOfRawData $"Section {index} raw size"
                ensureRange fileBytes rawOffset rawCount $"Section {index} raw data"

        // New arrays are zero-initialized, which models virtual tails and inter-section gaps.
        let mapped = Array.zeroCreate<byte> (checkedInt image.SizeOfImage "SizeOfImage")
        Array.Copy(fileBytes, 0, mapped, 0, headerCount)
        for section in image.Sections do
            if section.SizeOfRawData > 0u then
                Array.Copy(
                    fileBytes,
                    checkedInt section.PointerToRawData "Section raw offset",
                    mapped,
                    checkedInt section.VirtualAddress "Section RVA",
                    checkedInt section.SizeOfRawData "Section raw size")
        mapped)

    let applyRelocations (mappedImage: byte array) (image: PEImage) (actualBase: uint64) = asResult (fun () ->
        validateImage image
        if isNull mappedImage then invalid "Mapped image cannot be null"
        if mappedImage.Length <> checkedInt image.SizeOfImage "SizeOfImage" then
            invalid "Mapped image length does not equal SizeOfImage"
        let delta = BigInteger actualBase - BigInteger image.ImageBase
        let patched = Array.copy mappedImage
        for blockIndex, block in image.Relocations |> Array.indexed do
            requireArray $"Relocation block {blockIndex} entries" block.Entries
            if block.PageRVA >= image.SizeOfImage then invalid $"Relocation block {blockIndex} page is outside the image"
            for entryIndex, entry in block.Entries |> Array.indexed do
                let relocationType = int (entry >>> 12)
                let offsetInPage = uint32 (entry &&& 0x0FFFus)
                let target64 = uint64 block.PageRVA + uint64 offsetInPage
                if target64 > uint64 UInt32.MaxValue then
                    invalid $"Relocation block {blockIndex}, entry {entryIndex} RVA overflows"
                let target = uint32 target64
                match relocationType with
                | 0 -> () // IMAGE_REL_BASED_ABSOLUTE is padding.
                | 3 ->
                    let targetOffset, _ = ensureRvaRange patched target 4u $"Relocation block {blockIndex}, entry {entryIndex}"
                    let original = readU32 patched targetOffset "HIGHLOW relocation target"
                    let value = BigInteger original + delta
                    if value < BigInteger.Zero || value > BigInteger UInt32.MaxValue then
                        invalid $"Relocation block {blockIndex}, entry {entryIndex} overflows a 32-bit value"
                    BinaryPrimitives.WriteUInt32LittleEndian(Span<byte>(patched, targetOffset, 4), uint32 value)
                | 10 ->
                    let targetOffset, _ = ensureRvaRange patched target 8u $"Relocation block {blockIndex}, entry {entryIndex}"
                    let original = readU64 patched targetOffset "DIR64 relocation target"
                    let value = BigInteger original + delta
                    if value < BigInteger.Zero || value > BigInteger UInt64.MaxValue then
                        invalid $"Relocation block {blockIndex}, entry {entryIndex} overflows a 64-bit value"
                    BinaryPrimitives.WriteUInt64LittleEndian(Span<byte>(patched, targetOffset, 8), uint64 value)
                | unsupported ->
                    invalid $"Unsupported relocation type {unsupported} in block {blockIndex}, entry {entryIndex}"
        patched)

    let private readAsciiZ (mappedImage: byte array) rva description =
        let start = checkedInt rva description
        ensureRange mappedImage start 1 description
        let mutable finish = start
        while finish < mappedImage.Length && mappedImage[finish] <> 0uy do
            finish <- finish + 1
        if finish = mappedImage.Length then invalid $"{description} is not null-terminated"
        Text.Encoding.ASCII.GetString(mappedImage, start, finish - start)

    let enumerateImports (mappedImage: byte array) (image: PEImage) = asResult (fun () ->
        validateImage image
        if isNull mappedImage then invalid "Mapped image cannot be null"
        if mappedImage.Length <> checkedInt image.SizeOfImage "SizeOfImage" then
            invalid "Mapped image length does not equal SizeOfImage"
        let imports = ResizeArray<UnresolvedImport>()
        for descriptorIndex, descriptor in image.Imports |> Array.indexed do
            if descriptor.NameRVA = 0u then invalid $"Import descriptor {descriptorIndex} has no DLL name RVA"
            let dll = readAsciiZ mappedImage descriptor.NameRVA $"Import descriptor {descriptorIndex} DLL name"
            if String.IsNullOrWhiteSpace(dll) then invalid $"Import descriptor {descriptorIndex} has an empty DLL name"
            let thunkRva =
                if descriptor.OriginalFirstThunkRVA <> 0u then descriptor.OriginalFirstThunkRVA
                else descriptor.FirstThunkRVA
            if thunkRva = 0u then invalid $"Import descriptor {descriptorIndex} has no thunk table"
            let thunkStart = checkedInt thunkRva $"Import descriptor {descriptorIndex} thunk RVA"
            ensureRange mappedImage thunkStart 8 $"Import descriptor {descriptorIndex} thunk table"
            let maxEntries = (mappedImage.Length - thunkStart) / 8
            let mutable terminated = false
            let mutable thunkIndex = 0
            while not terminated && thunkIndex < maxEntries do
                let value = readU64 mappedImage (thunkStart + thunkIndex * 8) $"Import descriptor {descriptorIndex} thunk {thunkIndex}"
                if value = 0UL then
                    terminated <- true
                elif (value &&& 0x8000000000000000UL) <> 0UL then
                    if (value &&& 0x7FFFFFFFFFFF0000UL) <> 0UL then
                        invalid $"Import descriptor {descriptorIndex}, thunk {thunkIndex} has a malformed ordinal"
                    imports.Add({ Dll = dll; Name = None; Ordinal = Some(uint16 value); Hint = None })
                else
                    if value > uint64 UInt32.MaxValue then
                        invalid $"Import descriptor {descriptorIndex}, thunk {thunkIndex} name RVA is too large"
                    let nameRva = uint32 value
                    let hintOffset, _ = ensureRvaRange mappedImage nameRva 2u $"Import descriptor {descriptorIndex}, thunk {thunkIndex} hint"
                    let hint = readU16 mappedImage hintOffset "Import hint"
                    let functionNameRva = checkedRvaEnd nameRva 2u $"Import descriptor {descriptorIndex}, thunk {thunkIndex} name RVA"
                    let functionName = readAsciiZ mappedImage functionNameRva $"Import descriptor {descriptorIndex}, thunk {thunkIndex} function name"
                    if String.IsNullOrEmpty(functionName) then
                        invalid $"Import descriptor {descriptorIndex}, thunk {thunkIndex} has an empty function name"
                    imports.Add({ Dll = dll; Name = Some functionName; Ordinal = None; Hint = Some hint })
                thunkIndex <- thunkIndex + 1
            if not terminated then invalid $"Import descriptor {descriptorIndex} thunk table is not terminated"
        List.ofSeq imports)

    let deriveSectionProtections (image: PEImage) = asResult (fun () ->
        validateImage image
        image.Sections
        |> Array.map (fun section ->
            let readable = section.Characteristics &&& ImageScnMemRead <> 0u
            let writable = section.Characteristics &&& ImageScnMemWrite <> 0u
            let executable = section.Characteristics &&& ImageScnMemExecute <> 0u
            let protection =
                match executable, readable, writable with
                | false, false, false -> NoAccess
                | false, _, true -> ReadWrite // Windows writable pages are effectively readable.
                | false, true, false -> ReadOnly
                | true, false, false -> Execute
                | true, _, true -> ExecuteReadWrite
                | true, true, false -> ExecuteRead
            {
                Name = section.Name
                RVA = section.VirtualAddress
                Size = max section.VirtualSize section.SizeOfRawData
                Protection = protection
                Discardable = section.Characteristics &&& ImageScnMemDiscardable <> 0u
            })
        |> Array.toList)

module Loader =
    [<Literal>]
    let Version = 1u

    [<Literal>]
    let MinimumLoaderVersion = 1u

    [<Literal>]
    let PayloadVersion = 1u

module ReleaseMetadata =
    [<Literal>]
    let FormatVersion = 1us

    [<Literal>]
    let MinimumByteLength = 82

    [<Literal>]
    let MaximumSignatureLength = 4096

    [<Literal>]
    let Sha256Length = 32

    [<Literal>]
    let SigningKeyIdLength = 8

    type Architecture =
        | Amd64 = 1us

    type Metadata = {
        FormatVersion: uint16
        LoaderVersion: uint32
        PayloadVersion: uint32
        AbiVersion: uint32
        Architecture: Architecture
        PayloadLength: uint64
        Sha256: byte array
        Signature: byte array
        SigningKeyId: byte array
        ExpirationUnixSeconds: uint64
    }

    type MetadataConstraints = {
        MinimumLoaderVersion: uint32
        ExpectedAbiVersion: uint32
        ExpectedArchitecture: Architecture
        NowUnixSeconds: uint64
    }

    let private magic = Text.Encoding.ASCII.GetBytes("SYSVMETA")

    let private invalid message = raise (InvalidDataException(message))

    let private ensureRange (bytes: byte array) offset length description =
        if isNull bytes then invalid "Byte buffer cannot be null"
        if offset < 0 || length < 0 || offset > bytes.Length - length then
            invalid $"{description} is outside the byte buffer"

    let private readU16 bytes offset description =
        ensureRange bytes offset 2 description
        BinaryPrimitives.ReadUInt16LittleEndian(ReadOnlySpan<byte>(bytes, offset, 2))

    let private readU32 bytes offset description =
        ensureRange bytes offset 4 description
        BinaryPrimitives.ReadUInt32LittleEndian(ReadOnlySpan<byte>(bytes, offset, 4))

    let private readU64 bytes offset description =
        ensureRange bytes offset 8 description
        BinaryPrimitives.ReadUInt64LittleEndian(ReadOnlySpan<byte>(bytes, offset, 8))

    let deserialize (bytes: byte array) =
        if isNull bytes then nullArg "bytes"
        ensureRange bytes 0 MinimumByteLength "metadata"
        for index in 0 .. magic.Length - 1 do
            if bytes[index] <> magic[index] then invalid "Invalid metadata magic"
        let formatVersion = readU16 bytes 8 "format version"
        if formatVersion <> FormatVersion then
            invalid $"Unsupported metadata format version {formatVersion}"
        let loaderVersion = readU32 bytes 10 "loader version"
        let payloadVersion = readU32 bytes 14 "payload version"
        let abiVersion = readU32 bytes 18 "ABI version"
        let architectureRaw = readU16 bytes 22 "architecture"
        if architectureRaw <> uint16 Architecture.Amd64 then
            invalid "Architecture is not AMD64"
        let payloadLength = readU64 bytes 24 "payload length"
        ensureRange bytes 32 Sha256Length "SHA-256 digest"
        let sha256 = bytes[32 .. 32 + Sha256Length - 1]
        let signatureLength = int (readU16 bytes 64 "signature length")
        if signatureLength < 0 || signatureLength > MaximumSignatureLength then
            invalid "Signature length is outside the supported range"
        let signatureStart = 66
        ensureRange bytes signatureStart signatureLength "signature"
        let signature = bytes[signatureStart .. signatureStart + signatureLength - 1]
        let signingKeyIdStart = signatureStart + signatureLength
        ensureRange bytes signingKeyIdStart SigningKeyIdLength "signing key ID"
        let signingKeyId = bytes[signingKeyIdStart .. signingKeyIdStart + SigningKeyIdLength - 1]
        let expirationOffset = signingKeyIdStart + SigningKeyIdLength
        let expiration = readU64 bytes expirationOffset "expiration"
        {
            FormatVersion = formatVersion
            LoaderVersion = loaderVersion
            PayloadVersion = payloadVersion
            AbiVersion = abiVersion
            Architecture = Architecture.Amd64
            PayloadLength = payloadLength
            Sha256 = sha256
            Signature = signature
            SigningKeyId = signingKeyId
            ExpirationUnixSeconds = expiration
        }

    let serialize (metadata: Metadata) =
        if isNull metadata.Sha256 || metadata.Sha256.Length <> Sha256Length then
            invalid "SHA-256 must be 32 bytes"
        if isNull metadata.Signature || metadata.Signature.Length > MaximumSignatureLength then
            invalid "Signature is missing or too large"
        if isNull metadata.SigningKeyId || metadata.SigningKeyId.Length <> SigningKeyIdLength then
            invalid "Signing key ID must be 8 bytes"
        let buffer = Array.zeroCreate<byte> (66 + metadata.Signature.Length + SigningKeyIdLength + 8)
        Array.Copy(magic, 0, buffer, 0, magic.Length)
        BinaryPrimitives.WriteUInt16LittleEndian(Span<byte>(buffer, 8, 2), metadata.FormatVersion)
        BinaryPrimitives.WriteUInt32LittleEndian(Span<byte>(buffer, 10, 4), metadata.LoaderVersion)
        BinaryPrimitives.WriteUInt32LittleEndian(Span<byte>(buffer, 14, 4), metadata.PayloadVersion)
        BinaryPrimitives.WriteUInt32LittleEndian(Span<byte>(buffer, 18, 4), metadata.AbiVersion)
        BinaryPrimitives.WriteUInt16LittleEndian(Span<byte>(buffer, 22, 2), uint16 metadata.Architecture)
        BinaryPrimitives.WriteUInt64LittleEndian(Span<byte>(buffer, 24, 8), metadata.PayloadLength)
        Array.Copy(metadata.Sha256, 0, buffer, 32, Sha256Length)
        BinaryPrimitives.WriteUInt16LittleEndian(Span<byte>(buffer, 64, 2), uint16 metadata.Signature.Length)
        Array.Copy(metadata.Signature, 0, buffer, 66, metadata.Signature.Length)
        let signatureEnd = 66 + metadata.Signature.Length
        Array.Copy(metadata.SigningKeyId, 0, buffer, signatureEnd, SigningKeyIdLength)
        BinaryPrimitives.WriteUInt64LittleEndian(Span<byte>(buffer, signatureEnd + SigningKeyIdLength, 8), metadata.ExpirationUnixSeconds)
        buffer

    let validate (constraints: MetadataConstraints) (metadata: Metadata) = [
        if metadata.LoaderVersion < constraints.MinimumLoaderVersion then
            $"Loader version {metadata.LoaderVersion} is below minimum {constraints.MinimumLoaderVersion}"
        if metadata.AbiVersion <> constraints.ExpectedAbiVersion then
            $"ABI version {metadata.AbiVersion} does not match expected {constraints.ExpectedAbiVersion}"
        if metadata.Architecture <> constraints.ExpectedArchitecture then
            $"Architecture {metadata.Architecture} does not match expected {constraints.ExpectedArchitecture}"
        if metadata.ExpirationUnixSeconds <= constraints.NowUnixSeconds then
            $"Metadata expired at {metadata.ExpirationUnixSeconds}"
    ]

module SignatureVerification =
    let computeSha256 (bytes: byte array) =
        if isNull bytes then nullArg "bytes"
        use sha = SHA256.Create()
        sha.ComputeHash(bytes)

    let computeKeyId (publicKey: RSA) =
        if obj.ReferenceEquals(publicKey, null) then nullArg "publicKey"
        let keyBytes = publicKey.ExportRSAPublicKey()
        use sha = SHA256.Create()
        let hash = sha.ComputeHash(keyBytes)
        hash[0 .. ReleaseMetadata.SigningKeyIdLength - 1]

    let loadPublicKey (pemText: string) =
        if String.IsNullOrEmpty(pemText) then
            raise (InvalidDataException "Public key PEM is empty")
        let rsa = RSA.Create()
        rsa.ImportFromPem(pemText)
        rsa

    let loadPrivateKey (pemText: string) =
        if String.IsNullOrEmpty(pemText) then
            raise (InvalidDataException "Private key PEM is empty")
        let rsa = RSA.Create()
        rsa.ImportFromPem(pemText)
        rsa

    let signPayload (payload: byte array) (privateKey: RSA) =
        if isNull payload then nullArg "payload"
        if obj.ReferenceEquals(privateKey, null) then nullArg "privateKey"
        privateKey.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)

    let verifySignature (payload: byte array) (signature: byte array) (publicKey: RSA) =
        if isNull payload then nullArg "payload"
        if isNull signature then nullArg "signature"
        if obj.ReferenceEquals(publicKey, null) then nullArg "publicKey"
        publicKey.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)

    let generateKeyPair () =
        use rsa = RSA.Create(2048)
        rsa.ExportRSAPrivateKeyPem(), rsa.ExportRSAPublicKeyPem()

module PinnedKey =
    let PublicKeyPem =
        "-----BEGIN RSA PUBLIC KEY-----\n" +
        "MIIBCgKCAQEAqUdhRtd77AO80+h3kH32YtW+DjLm3xRILwaocmH9D8EfGeRMciWZ\n" +
        "J2AZUhaRFd7a0VEV0uJaj4+8SFVn+/mG07QdRKAcGV3CltOQDMh0QT5ZIVf8A0j3\n" +
        "6qlNjI+4AhnaDJ5sY0ohQ9Oo9fUw9Snsn9xSHax0ocVHwbND+HEfYXcKBNyPWKFB\n" +
        "IraSkoL7+K5jF6i3FSOQyhfhTWJhOOn0pxHf9cNFsU6MoV+nInJOfGWiLqBEY3jC\n" +
        "Zn+WcmctIIPY+j6kw4Wy5zbslVN/TBFThYoYrkhQ1voEmz0alFEEiPGAlJlJyfZo\n" +
        "M4qJzg/+8x1Ne6IT0mXut4SDFVH5MEC5ZQIDAQAB\n" +
        "-----END RSA PUBLIC KEY-----"

    let load () = SignatureVerification.loadPublicKey(PublicKeyPem)

module Acquisition =
    [<Literal>]
    let DefaultTimeoutSeconds = 30

    [<Literal>]
    let MaximumPayloadBytes = 8388608

    type AcquisitionConfig = {
        BaseUrl: string
        MetadataPath: string
        PayloadPath: string
        TimeoutSeconds: int
    }

    let defaultConfig baseUrl = {
        BaseUrl = baseUrl
        MetadataPath = "app.meta"
        PayloadPath = "jvm_helper.dll"
        TimeoutSeconds = DefaultTimeoutSeconds
    }

    let private invalid message = raise (InvalidDataException(message))

    let private client = lazy (
        let handler = new SocketsHttpHandler()
        handler.PooledConnectionLifetime <- TimeSpan.FromMinutes(2.0)
        let value = new HttpClient(handler)
        value.Timeout <- Timeout.InfiniteTimeSpan
        value)

    let private readAllBytes (response: HttpResponseMessage) (cancellationToken: CancellationToken) =
        let contentLength = response.Content.Headers.ContentLength
        if contentLength.HasValue && contentLength.Value > int64 MaximumPayloadBytes then
            invalid "Response exceeds the maximum payload size"
        use content = response.Content.ReadAsStreamAsync(cancellationToken).GetAwaiter().GetResult()
        let buffer = Array.zeroCreate<byte> 8192
        use output = new MemoryStream()
        let mutable total = 0L
        let mutable more = true
        while more do
            let read = content.ReadAsync(Memory<byte>(buffer), cancellationToken).AsTask().GetAwaiter().GetResult()
            if read = 0 then
                more <- false
            else
                total <- total + int64 read
                if total > int64 MaximumPayloadBytes then
                    invalid "Payload exceeds the maximum allowed size"
                output.Write(buffer, 0, read)
        output.ToArray()

    let download (config: AcquisitionConfig) (cancellationToken: CancellationToken) =
        try
            use timeout = new CancellationTokenSource(TimeSpan.FromSeconds(float config.TimeoutSeconds))
            use linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token)
            let requestToken = linked.Token
            let base_ = config.BaseUrl.TrimEnd('/')
            let metadataUrl = $"{base_}/{config.MetadataPath}"
            let payloadUrl = $"{base_}/{config.PayloadPath}"

            use metadataResponse =
                client.Value
                    .GetAsync(metadataUrl, HttpCompletionOption.ResponseHeadersRead, requestToken)
                    .GetAwaiter()
                    .GetResult()
            if not metadataResponse.IsSuccessStatusCode then
                invalid $"Metadata download failed: HTTP {int metadataResponse.StatusCode}"
            let metadataBytes = readAllBytes metadataResponse requestToken

            use payloadResponse =
                client.Value
                    .GetAsync(payloadUrl, HttpCompletionOption.ResponseHeadersRead, requestToken)
                    .GetAwaiter()
                    .GetResult()
            if not payloadResponse.IsSuccessStatusCode then
                invalid $"Payload download failed: HTTP {int payloadResponse.StatusCode}"
            let payloadBytes = readAllBytes payloadResponse requestToken

            Ok(metadataBytes, payloadBytes)
        with
        | :? InvalidDataException as error -> Error error.Message
        | :? TaskCanceledException -> Error "Download timed out or was cancelled"
        | :? HttpRequestException as error -> Error $"Network error: {error.Message}"
        | error -> Error $"Acquisition failed: {error.Message}"

module TargetDiscovery =
    [<Literal>]
    let private ProcessQueryLimitedInformation = 0x1000u

    [<Literal>]
    let private Synchronize = 0x00100000u

    [<Literal>]
    let private WaitObject0 = 0u

    [<Literal>]
    let private WaitTimeout = 258u

    [<Literal>]
    let private ImageFileMachineUnknown = 0us

    [<Literal>]
    let private ImageFileMachineI386 = 0x014Cus

    [<Literal>]
    let private ImageFileMachineAmd64 = 0x8664us

    [<Literal>]
    let private ImageFileMachineArm64 = 0xAA64us

    [<Struct; StructLayout(LayoutKind.Sequential)>]
    type private FileTime = {
        LowDateTime: uint32
        HighDateTime: uint32
    }

    type private EnumWindowsProc = delegate of nativeint * nativeint -> bool

    module private Native =
        [<DllImport("user32.dll", SetLastError = true)>]
        extern bool EnumWindows(EnumWindowsProc callback, nativeint parameter)

        [<DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
        extern int GetClassNameW(nativeint window, StringBuilder className, int maximumCount)

        [<DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
        extern int GetWindowTextW(nativeint window, StringBuilder title, int maximumCount)

        [<DllImport("user32.dll", SetLastError = true)>]
        extern uint32 GetWindowThreadProcessId(nativeint window, uint32& processId)

        [<DllImport("user32.dll")>]
        extern bool IsWindow(nativeint window)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern SafeProcessHandle OpenProcess(uint32 desiredAccess, bool inheritHandle, uint32 processId)

        [<DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
        extern bool QueryFullProcessImageNameW(
            SafeProcessHandle processHandle,
            uint32 flags,
            StringBuilder executablePath,
            uint32& size)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool GetProcessTimes(
            SafeProcessHandle processHandle,
            FileTime& creationTime,
            FileTime& exitTime,
            FileTime& kernelTime,
            FileTime& userTime)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool IsWow64Process2(
            SafeProcessHandle processHandle,
            uint16& processMachine,
            uint16& nativeMachine)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool IsWow64Process(SafeProcessHandle processHandle, bool& wow64Process)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern uint32 WaitForSingleObject(SafeProcessHandle handle, uint32 milliseconds)

    type ProcessArchitecture =
        | X86
        | X64
        | Arm64
        | Unknown of uint16

    type Target internal (
        windowHandle: nativeint,
        processId: uint32,
        processHandle: SafeProcessHandle,
        executablePath: string,
        windowTitle: string,
        windowClass: string,
        architecture: ProcessArchitecture,
        creationTimeUtc: DateTimeOffset) =

        member _.WindowHandle = windowHandle
        member _.ProcessId = processId
        member _.ProcessHandle = processHandle
        member _.ExecutablePath = executablePath
        member _.WindowTitle = windowTitle
        member _.WindowClass = windowClass
        member _.Architecture = architecture
        member _.CreationTimeUtc = creationTimeUtc
        member _.IsExpectedJavaProcess =
            let name = Path.GetFileName(executablePath)
            name.Equals("javaw.exe", StringComparison.OrdinalIgnoreCase)
            || name.Equals("java.exe", StringComparison.OrdinalIgnoreCase)

        interface IDisposable with
            member _.Dispose() = processHandle.Dispose()

    type Discovery = {
        Targets: Target list
        Issues: string list
    }

    let private supportedClasses = set [ "LWJGL"; "LWJGL3"; "GLFW30" ]

    let private win32Error operation =
        let code = Marshal.GetLastWin32Error()
        $"{operation} failed with Win32 error {code}"

    let private className window =
        let buffer = StringBuilder(256)
        let length = Native.GetClassNameW(window, buffer, buffer.Capacity)
        if length <= 0 then Error(win32Error "GetClassNameW")
        else Ok(buffer.ToString())

    let private windowTitle window =
        let buffer = StringBuilder(1024)
        let length = Native.GetWindowTextW(window, buffer, buffer.Capacity)
        if length <= 0 then "" else buffer.ToString()

    let private executablePath (processHandle: SafeProcessHandle) =
        let buffer = StringBuilder(32768)
        let mutable length = uint32 buffer.Capacity
        if Native.QueryFullProcessImageNameW(processHandle, 0u, buffer, &length) then
            buffer.ToString()
        else
            raise (InvalidOperationException(win32Error "QueryFullProcessImageNameW"))

    let private creationTime (processHandle: SafeProcessHandle) =
        let mutable created = Unchecked.defaultof<FileTime>
        let mutable exited = Unchecked.defaultof<FileTime>
        let mutable kernel = Unchecked.defaultof<FileTime>
        let mutable user = Unchecked.defaultof<FileTime>
        if not (Native.GetProcessTimes(processHandle, &created, &exited, &kernel, &user)) then
            raise (InvalidOperationException(win32Error "GetProcessTimes"))
        let ticks = (uint64 created.HighDateTime <<< 32) ||| uint64 created.LowDateTime
        DateTimeOffset.FromFileTime(int64 ticks).ToUniversalTime()

    let private architecture (processHandle: SafeProcessHandle) =
        let fromMachine = function
            | ImageFileMachineI386 -> X86
            | ImageFileMachineAmd64 -> X64
            | ImageFileMachineArm64 -> Arm64
            | value -> Unknown value

        try
            let mutable processMachine = 0us
            let mutable nativeMachine = 0us
            if not (Native.IsWow64Process2(processHandle, &processMachine, &nativeMachine)) then
                raise (InvalidOperationException(win32Error "IsWow64Process2"))
            if processMachine = ImageFileMachineUnknown then fromMachine nativeMachine
            else fromMachine processMachine
        with
        | :? EntryPointNotFoundException ->
            let mutable wow64 = false
            if not (Native.IsWow64Process(processHandle, &wow64)) then
                raise (InvalidOperationException(win32Error "IsWow64Process"))
            if wow64 then X86
            elif Environment.Is64BitOperatingSystem then X64
            else X86

    let private createTarget window windowClass =
        let mutable processId = 0u
        if Native.GetWindowThreadProcessId(window, &processId) = 0u || processId = 0u then
            Error(win32Error "GetWindowThreadProcessId")
        else
            let processHandle = Native.OpenProcess(ProcessQueryLimitedInformation ||| Synchronize, false, processId)
            if isNull processHandle || processHandle.IsInvalid then
                if not (isNull processHandle) then processHandle.Dispose()
                Error(win32Error $"OpenProcess({processId})")
            else
                try
                    let path = executablePath processHandle
                    let created = creationTime processHandle
                    let machine = architecture processHandle
                    Ok(new Target(window, processId, processHandle, path, windowTitle window, windowClass, machine, created))
                with error ->
                    processHandle.Dispose()
                    Error error.Message

    let discover () =
        let windows = ResizeArray<nativeint * string>()
        let issues = ResizeArray<string>()
        let callback = EnumWindowsProc(fun window _ ->
            match className window with
            | Ok name when supportedClasses.Contains(name) -> windows.Add(window, name)
            | Ok _ -> ()
            | Error _ -> ()
            true)

        if not (Native.EnumWindows(callback, 0n)) then
            issues.Add(win32Error "EnumWindows")

        let targets = ResizeArray<Target>()
        for window, windowClass in windows do
            match createTarget window windowClass with
            | Ok target -> targets.Add(target)
            | Error message -> issues.Add($"Window 0x{uint64 window:X}: {message}")
        { Targets = List.ofSeq targets; Issues = List.ofSeq issues }

    let revalidate (target: Target) = [
        if not (Native.IsWindow(target.WindowHandle)) then
            "Selected window no longer exists"
        else
            let mutable currentProcessId = 0u
            if Native.GetWindowThreadProcessId(target.WindowHandle, &currentProcessId) = 0u then
                win32Error "GetWindowThreadProcessId"
            elif currentProcessId <> target.ProcessId then
                $"Selected window now belongs to PID {currentProcessId}, not PID {target.ProcessId}"

        match Native.WaitForSingleObject(target.ProcessHandle, 0u) with
        | WaitTimeout -> ()
        | WaitObject0 -> "Target process has exited"
        | _ -> win32Error "WaitForSingleObject"

        try
            if creationTime target.ProcessHandle <> target.CreationTimeUtc then
                "Target process creation time changed"
        with error ->
            error.Message

        if target.Architecture <> X64 then
            $"Target architecture is {target.Architecture}, not X64"
        if not target.IsExpectedJavaProcess then
            $"Target executable is not javaw.exe or java.exe: {target.ExecutablePath}"
    ]

module IpcAbi =
    [<Literal>]
    let Magic = 0x484D564Au

    [<Literal>]
    let Version = 1u

    [<Literal>]
    let MappingSize = 1024

    [<Literal>]
    let HeaderSize = 128

    [<Literal>]
    let ConfigOffset = 128

    [<Literal>]
    let ConfigSize = 336

    [<Literal>]
    let private GenerationOffset = 16

    [<Literal>]
    let private LoaderStateOffset = 24

    [<Literal>]
    let private PayloadStateOffset = 28

    [<Literal>]
    let private ErrorCodeOffset = 32

    [<Literal>]
    let private LoaderHeartbeatOffset = 64

    [<Literal>]
    let private LastAcceptedGenerationOffset = 80

    [<Literal>]
    let private StopRequestOffset = 88

    [<Literal>]
    let private StopAckOffset = 92

    [<Literal>]
    let private PageReadWrite = 0x04u

    [<Literal>]
    let private FileMapAllAccess = 0x000F001Fu

    [<Literal>]
    let private Infinite = 0xFFFFFFFFu

    type LifecycleState =
        | None = 0
        | Starting = 1
        | Ready = 2
        | Stopping = 3
        | Stopped = 4
        | Failed = 5

    type TargetIdentity = {
        WindowHandle: uint64
        ProcessId: uint32
        CreationTimeFileTime: int64
    }

    type Names = {
        Token: string
    }

    type Status = {
        Generation: int
        LoaderState: LifecycleState
        PayloadState: LifecycleState
        ErrorCode: int
        LoaderHeartbeatUnixMillis: int64
        LastAcceptedGeneration: int
    }

    [<Struct; StructLayout(LayoutKind.Sequential)>]
    type private SecurityAttributes = {
        Length: uint32
        SecurityDescriptor: nativeint
        InheritHandle: int32
    }

    module private Native =
        [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
        extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string descriptor,
            uint32 revision,
            nativeint& securityDescriptor,
            uint32& descriptorSize)

        [<DllImport("kernel32.dll")>]
        extern nativeint LocalFree(nativeint memory)

        [<DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
        extern SafeFileHandle CreateFileMappingW(
            nativeint file,
            SecurityAttributes& attributes,
            uint32 protection,
            uint32 maximumSizeHigh,
            uint32 maximumSizeLow,
            string name)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern nativeint MapViewOfFile(
            SafeFileHandle mapping,
            uint32 desiredAccess,
            uint32 offsetHigh,
            uint32 offsetLow,
            unativeint bytesToMap)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool UnmapViewOfFile(nativeint address)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool DuplicateHandle(
            SafeProcessHandle sourceProcess,
            SafeHandle sourceHandle,
            SafeProcessHandle targetProcess,
            nativeint& targetHandle,
            uint32 desiredAccess,
            bool inheritHandle,
            uint32 options)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool CloseHandle(nativeint handle)

    let private win32Error operation =
        let code = Marshal.GetLastWin32Error()
        InvalidOperationException($"{operation} failed with Win32 error {code}")

    let private pointer address offset = IntPtr.Add(address, offset)

    let private writeU32 (bytes: byte array) offset value =
        BinaryPrimitives.WriteUInt32LittleEndian(Span<byte>(bytes, offset, 4), value)

    let private writeI32 (bytes: byte array) offset value =
        BinaryPrimitives.WriteInt32LittleEndian(Span<byte>(bytes, offset, 4), value)

    let private writeU64 (bytes: byte array) offset value =
        BinaryPrimitives.WriteUInt64LittleEndian(Span<byte>(bytes, offset, 8), value)

    let private writeI64 (bytes: byte array) offset value =
        BinaryPrimitives.WriteInt64LittleEndian(Span<byte>(bytes, offset, 8), value)

    let private readI32 (bytes: byte array) offset =
        BinaryPrimitives.ReadInt32LittleEndian(ReadOnlySpan<byte>(bytes, offset, 4))

    let private readU32 (bytes: byte array) offset =
        BinaryPrimitives.ReadUInt32LittleEndian(ReadOnlySpan<byte>(bytes, offset, 4))

    let private lifecycle value =
        if Enum.IsDefined(typeof<LifecycleState>, value) then enum<LifecycleState>(value)
        else LifecycleState.Failed

    let private boolValue value = if value then 1 else 0

    let serializeConfig (config: Configuration.Config) =
        let errors = Configuration.validate config
        if not errors.IsEmpty then
            raise (InvalidDataException(errors |> String.concat "; "))
        let bytes = Array.zeroCreate<byte> ConfigSize
        let fields = [|
            int config.Version
            boolValue config.Left.Enabled
            config.Left.MinimumCps
            config.Left.MaximumCps
            int config.Left.Randomization
            boolValue config.Left.HoldToClick
            boolValue config.LeftTriggerMode
            boolValue config.LeftBreakBlocks
            config.LeftBreakDelayMinimum
            config.LeftBreakDelayMaximum
            boolValue config.LeftBreakWhitelist
            boolValue config.Right.Enabled
            config.Right.MinimumCps
            config.Right.MaximumCps
            int config.Right.Randomization
            boolValue config.Right.HoldToClick
            config.RightStartDelayMillis
            boolValue config.RightUseItemWhitelist
            config.RightWhitelist.Length
        |]
        fields |> Array.iteri (fun index value -> writeI32 bytes (index * 4) value)
        config.RightWhitelist
        |> List.iteri (fun index item ->
            let encoded = Encoding.UTF8.GetBytes(item)
            Array.Copy(encoded, 0, bytes, 76 + index * 32, encoded.Length))
        writeI32 bytes 332 (boolValue config.HitFlickEnabled)
        bytes

    let deserializeConfig (bytes: byte array) =
        if isNull bytes || bytes.Length <> ConfigSize then
            raise (InvalidDataException($"Configuration snapshot must be {ConfigSize} bytes"))
        let value index = readI32 bytes (index * 4)
        let mode index = enum<Configuration.RandomizationMode>(value index)
        let whitelistCount = value 18
        if whitelistCount < 0 || whitelistCount > Configuration.MaximumWhitelistEntries then
            raise (InvalidDataException("Whitelist count is outside the ABI range"))
        let whitelist = [
            for index in 0 .. whitelistCount - 1 do
                let offset = 76 + index * 32
                let count =
                    bytes[offset .. offset + 31]
                    |> Array.tryFindIndex ((=) 0uy)
                    |> Option.defaultValue 32
                yield Encoding.UTF8.GetString(bytes, offset, count)
        ]
        let config = {
            Configuration.Version = uint32 (value 0)
            Configuration.Left = {
                Enabled = value 1 <> 0
                MinimumCps = value 2
                MaximumCps = value 3
                Randomization = mode 4
                HoldToClick = value 5 <> 0
            }
            Configuration.LeftTriggerMode = value 6 <> 0
            Configuration.LeftBreakBlocks = value 7 <> 0
            Configuration.LeftBreakDelayMinimum = value 8
            Configuration.LeftBreakDelayMaximum = value 9
            Configuration.LeftBreakWhitelist = value 10 <> 0
            Configuration.Right = {
                Enabled = value 11 <> 0
                MinimumCps = value 12
                MaximumCps = value 13
                Randomization = mode 14
                HoldToClick = value 15 <> 0
            }
            Configuration.RightStartDelayMillis = value 16
            Configuration.RightUseItemWhitelist = value 17 <> 0
            Configuration.RightWhitelist = whitelist
            Configuration.HitFlickEnabled = readI32 bytes 332 <> 0
        }
        let errors = Configuration.validate config
        if not errors.IsEmpty then
            raise (InvalidDataException(errors |> String.concat "; "))
        config

    let createNames () =
        let token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()
        { Token = token }

    let targetIdentity (target: TargetDiscovery.Target) = {
        WindowHandle = uint64 target.WindowHandle
        ProcessId = target.ProcessId
        CreationTimeFileTime = target.CreationTimeUtc.ToFileTime()
    }

    let private createCurrentUserSecurity () =
        use identity = WindowsIdentity.GetCurrent()
        let sid = identity.User
        if isNull sid then invalidOp "Current Windows identity has no user SID"
        let sddl = $"D:P(A;;GA;;;{sid.Value})"
        let mutable descriptor = 0n
        let mutable descriptorSize = 0u
        if not (Native.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1u, &descriptor, &descriptorSize)) then
            raise (win32Error "ConvertStringSecurityDescriptorToSecurityDescriptorW")
        let attributes = {
            Length = uint32 (Marshal.SizeOf<SecurityAttributes>())
            SecurityDescriptor = descriptor
            InheritHandle = 0
        }
        descriptor, attributes

    type Session private (
        names: Names,
        mapping: SafeFileHandle,
        view: nativeint) =

        let mutable disposed = false

        member _.Names = names
        member _.IsDisposed = disposed
        member _.MappingHandle = mapping
        member _.View = view

        member _.Publish(config: Configuration.Config) =
            if disposed then raise (ObjectDisposedException(nameof Session))
            let snapshot = serializeConfig config
            let current = Marshal.ReadInt32(pointer view GenerationOffset)
            let stable = if current &&& 1 = 0 then current else current + 1
            let odd = stable + 1
            let even = stable + 2
            Marshal.WriteInt32(pointer view GenerationOffset, odd)
            Thread.MemoryBarrier()
            Marshal.Copy(snapshot, 0, pointer view ConfigOffset, snapshot.Length)
            Marshal.WriteInt64(pointer view LoaderHeartbeatOffset, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
            Thread.MemoryBarrier()
            Marshal.WriteInt32(pointer view GenerationOffset, even)
            even

        member _.TryReadStable() =
            if disposed then raise (ObjectDisposedException(nameof Session))
            let first = Marshal.ReadInt32(pointer view GenerationOffset)
            if first = 0 || first &&& 1 <> 0 then None
            else
                let bytes = Array.zeroCreate<byte> ConfigSize
                Marshal.Copy(pointer view ConfigOffset, bytes, 0, bytes.Length)
                Thread.MemoryBarrier()
                let second = Marshal.ReadInt32(pointer view GenerationOffset)
                if first = second && second &&& 1 = 0 then Some(second, deserializeConfig bytes)
                else None

        member _.SetLoaderState(state: LifecycleState, errorCode: int) =
            if disposed then raise (ObjectDisposedException(nameof Session))
            Marshal.WriteInt32(pointer view LoaderStateOffset, int state)
            Marshal.WriteInt32(pointer view ErrorCodeOffset, errorCode)

        member _.SetPayloadState(state: LifecycleState, errorCode: int, acceptedGeneration: int) =
            if disposed then raise (ObjectDisposedException(nameof Session))
            Marshal.WriteInt32(pointer view PayloadStateOffset, int state)
            Marshal.WriteInt32(pointer view ErrorCodeOffset, errorCode)
            Marshal.WriteInt32(pointer view LastAcceptedGenerationOffset, acceptedGeneration)

        member _.TouchHeartbeat() =
            if disposed then raise (ObjectDisposedException(nameof Session))
            Marshal.WriteInt64(pointer view LoaderHeartbeatOffset, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())

        member _.ReadStatus() =
            if disposed then raise (ObjectDisposedException(nameof Session))
            Thread.MemoryBarrier()
            {
                Generation = Marshal.ReadInt32(pointer view GenerationOffset)
                LoaderState = lifecycle (Marshal.ReadInt32(pointer view LoaderStateOffset))
                PayloadState = lifecycle (Marshal.ReadInt32(pointer view PayloadStateOffset))
                ErrorCode = Marshal.ReadInt32(pointer view ErrorCodeOffset)
                LoaderHeartbeatUnixMillis = Marshal.ReadInt64(pointer view LoaderHeartbeatOffset)
                LastAcceptedGeneration = Marshal.ReadInt32(pointer view LastAcceptedGenerationOffset)
            }

        member _.RequestStop() =
            if disposed then raise (ObjectDisposedException(nameof Session))
            Marshal.WriteInt32(pointer view StopRequestOffset, 1)

        member _.SignalStopAck() =
            if disposed then raise (ObjectDisposedException(nameof Session))
            Marshal.WriteInt32(pointer view StopAckOffset, 1)

        member _.WaitForStopAcknowledgement(timeout: TimeSpan) =
            if disposed then raise (ObjectDisposedException(nameof Session))
            let deadline = DateTimeOffset.UtcNow + timeout
            let mutable acked = false
            while not acked && DateTimeOffset.UtcNow < deadline do
                acked <- Marshal.ReadInt32(pointer view StopAckOffset) <> 0
                if not acked then Thread.Sleep(50)
            acked

        interface IDisposable with
            member _.Dispose() =
                if not disposed then
                    disposed <- true
                    if view <> 0n then Native.UnmapViewOfFile(view) |> ignore
                    mapping.Dispose()

        static member Create(identity: TargetIdentity, initialConfig: Configuration.Config) =
            let names = createNames()
            let descriptor, attributesValue = createCurrentUserSecurity()
            let mutable attributes = attributesValue
            try
                let mapping = Native.CreateFileMappingW(nativeint -1, &attributes, PageReadWrite, 0u, uint32 MappingSize, null)
                if isNull mapping || mapping.IsInvalid then raise (win32Error "CreateFileMappingW")
                let mutable view = 0n
                try
                    view <- Native.MapViewOfFile(mapping, FileMapAllAccess, 0u, 0u, unativeint MappingSize)
                    if view = 0n then raise (win32Error "MapViewOfFile")

                    let header = Array.zeroCreate<byte> HeaderSize
                    writeU32 header 0 Magic
                    writeU32 header 4 (uint32 MappingSize)
                    writeU32 header 8 Version
                    writeU32 header 12 (uint32 HeaderSize)
                    writeU32 header 20 (uint32 ConfigSize)
                    writeI32 header LoaderStateOffset (int LifecycleState.Starting)
                    writeI32 header PayloadStateOffset (int LifecycleState.None)
                    writeU64 header 40 identity.WindowHandle
                    writeU32 header 48 identity.ProcessId
                    writeI64 header 56 identity.CreationTimeFileTime
                    writeI64 header LoaderHeartbeatOffset (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())
                    writeU32 header 104 (uint32 ConfigOffset)
                    writeU32 header 108 (uint32 ConfigSize)
                    Marshal.Copy(header, 0, view, header.Length)
                    let session = new Session(names, mapping, view)
                    session.Publish(initialConfig) |> ignore
                    session
                with
                | error ->
                    if view <> 0n then Native.UnmapViewOfFile(view) |> ignore
                    mapping.Dispose()
                    raise error
            finally
                Native.LocalFree(descriptor) |> ignore

    let selfTest () =
        let identity = {
            WindowHandle = 0UL
            ProcessId = uint32 Environment.ProcessId
            CreationTimeFileTime = DateTimeOffset.UtcNow.ToFileTime()
        }
        use session = Session.Create(identity, Configuration.defaults)
        if session.Names.Token.Length <> 32 then
            Error "Run token is not 128 bits"
        else
            match session.TryReadStable() with
            | None -> Error "Could not read a stable initial snapshot"
            | Some(generation, config) when config <> Configuration.defaults -> Error "Configuration round-trip changed values"
            | Some(generation, _) when generation <= 0 || generation &&& 1 <> 0 -> Error "Published generation is not stable and even"
            | Some(generation, _) ->
                session.SetPayloadState(LifecycleState.Ready, 0, generation)
                session.SetLoaderState(LifecycleState.Ready, 0)
                session.TouchHeartbeat()
                let status = session.ReadStatus()
                if status.PayloadState <> LifecycleState.Ready
                    || status.LoaderState <> LifecycleState.Ready
                    || status.LastAcceptedGeneration <> generation then
                    Error "Lifecycle status round-trip changed values"
                else
                    session.RequestStop()
                    session.SignalStopAck()
                    if session.WaitForStopAcknowledgement(TimeSpan.FromSeconds(1.0)) then Ok(session.Names, generation)
                    else Error "Stop acknowledgement timed out"

    /// Cross-language ABI verification: compares F# IpcAbi constants against
    /// the expected values from src/jvm_helper.h.  Both sides must agree on
    /// magic, version, sizes, and every header field offset.
    let verifyCHeader () = [
        if Magic <> 0x484D564Au then
            $"Magic mismatch: F#={Magic} C=0x484D564A"
        if Version <> 1u then
            $"Version mismatch: F#={Version} C=1"
        if MappingSize <> 1024 then
            $"MappingSize mismatch: F#={MappingSize} C=1024"
        if HeaderSize <> 128 then
            $"HeaderSize mismatch: F#={HeaderSize} C=128"
        if ConfigOffset <> 128 then
            $"ConfigOffset mismatch: F#={ConfigOffset} C=128"
        if ConfigSize <> 336 then
            $"ConfigSize mismatch: F#={ConfigSize} C=336"
        if GenerationOffset <> 16 then
            $"GenerationOffset mismatch: F#={GenerationOffset} C=16"
        if LoaderStateOffset <> 24 then
            $"LoaderStateOffset mismatch: F#={LoaderStateOffset} C=24"
        if PayloadStateOffset <> 28 then
            $"PayloadStateOffset mismatch: F#={PayloadStateOffset} C=28"
        if ErrorCodeOffset <> 32 then
            $"ErrorCodeOffset mismatch: F#={ErrorCodeOffset} C=32"
        if LoaderHeartbeatOffset <> 64 then
            $"LoaderHeartbeatOffset mismatch: F#={LoaderHeartbeatOffset} C=64"
        if LastAcceptedGenerationOffset <> 80 then
            $"LastAcceptedGenerationOffset mismatch: F#={LastAcceptedGenerationOffset} C=80"
        if StopRequestOffset <> 88 then
            $"StopRequestOffset mismatch: F#={StopRequestOffset} C=88"
        if StopAckOffset <> 92 then
            $"StopAckOffset mismatch: F#={StopAckOffset} C=92"
        if Configuration.Version <> 3u then
            $"ConfigVersion mismatch: F#={Configuration.Version} C=3"
    ]

module ManualMap =
    [<Literal>]
    let private ProcessVmOperation = 0x0008u

    [<Literal>]
    let private ProcessVmRead = 0x0010u

    [<Literal>]
    let private ProcessVmWrite = 0x0020u

    [<Literal>]
    let private ProcessCreateThread = 0x0002u

    [<Literal>]
    let private ProcessDupHandle = 0x0040u

    [<Literal>]
    let private ProcessQueryInformation = 0x0400u

    [<Literal>]
    let private MemCommit = 0x1000u

    [<Literal>]
    let private MemReserve = 0x2000u

    [<Literal>]
    let private MemRelease = 0x8000u

    [<Literal>]
    let private PageExecuteReadWrite = 0x40u

    [<Literal>]
    let private PageReadWrite = 0x04u

    [<Literal>]
    let private Th32csSnapmodules = 0x00000008u

    [<Literal>]
    let private Th32csSnapmodule32 = 0x00000010u

    [<Literal>]
    let private ModuleEntrySize = 1080

    [<Literal>]
    let private ModBaseAddrOffset = 24

    [<Literal>]
    let private ModNameOffset = 48

    [<Literal>]
    let private JvmCtxMagic = 0x544D564Au

    [<Literal>]
    let private JvmCtxVersion = 1u

    [<Literal>]
    let private JvmCtxSize = 392

    [<Literal>]
    let private JvmCtxConfigOffset = 56

    module private Native =
        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern SafeProcessHandle OpenProcess(uint32 access, bool inheritHandle, uint32 pid)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern nativeint VirtualAllocEx(SafeProcessHandle proc, nativeint address, uint64 size, uint32 allocationType, uint32 protection)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool VirtualFreeEx(SafeProcessHandle proc, nativeint address, uint64 size, uint32 freeType)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool WriteProcessMemory(SafeProcessHandle proc, nativeint baseAddress, byte[] buffer, nativeint size, nativeint bytesWritten)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool ReadProcessMemory(SafeProcessHandle proc, nativeint baseAddress, byte[] buffer, nativeint size, nativeint& bytesRead)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern SafeWaitHandle CreateRemoteThread(SafeProcessHandle proc, nativeint attributes, uint32 stackSize, nativeint startAddress, nativeint parameter, uint32 flags, uint32& threadId)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool GetThreadContext(SafeWaitHandle thread, nativeint context)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool SetThreadContext(SafeWaitHandle thread, nativeint context)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern uint32 ResumeThread(SafeWaitHandle thread)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool FlushInstructionCache(SafeProcessHandle proc, nativeint baseAddress, nativeint size)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern nativeint CreateToolhelp32Snapshot(uint32 flags, uint32 processId)

        [<DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)>]
        extern bool Module32FirstW(nativeint snapshot, nativeint entry)

        [<DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)>]
        extern bool Module32NextW(nativeint snapshot, nativeint entry)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool CloseHandle(nativeint handle)

        [<DllImport("kernel32.dll", SetLastError = true)>]
        extern bool DuplicateHandle(
            SafeProcessHandle sourceProcess,
            SafeHandle sourceHandle,
            SafeProcessHandle targetProcess,
            nativeint& targetHandle,
            uint32 desiredAccess,
            bool inheritHandle,
            uint32 options)

        [<DllImport("kernel32.dll")>]
        extern SafeProcessHandle GetCurrentProcess()

    let private win32Error operation =
        let code = Marshal.GetLastWin32Error()
        $"{operation} failed with Win32 error {code}"

    let private readU16 (b: byte[]) o = BinaryPrimitives.ReadUInt16LittleEndian(ReadOnlySpan(b, o, 2))
    let private readU32 (b: byte[]) o = BinaryPrimitives.ReadUInt32LittleEndian(ReadOnlySpan(b, o, 4))
    let private readU64 (b: byte[]) o = BinaryPrimitives.ReadUInt64LittleEndian(ReadOnlySpan(b, o, 8))
    let private writeU32 (b: byte[]) o v = BinaryPrimitives.WriteUInt32LittleEndian(Span(b, o, 4), v)
    let private writeU64 (b: byte[]) o v = BinaryPrimitives.WriteUInt64LittleEndian(Span(b, o, 8), v)

    let private rvaToFileOffset (bytes: byte[]) rva =
        let ntOff = int (readU32 bytes 0x3C)
        let sectionCount = int (readU16 bytes (ntOff + 6))
        let optionalSize = int (readU16 bytes (ntOff + 20))
        let sectionTable = ntOff + 24 + optionalSize
        let mutable result = None
        for i in 0 .. sectionCount - 1 do
            if result.IsNone then
                let off = sectionTable + i * 40
                let va = readU32 bytes (off + 12)
                let vs = readU32 bytes (off + 8)
                let rawSize = readU32 bytes (off + 16)
                let vsize = if vs <> 0u then vs else rawSize
                if rva >= va && rva < va + vsize then
                    let rawOff = readU32 bytes (off + 20)
                    result <- Some(int rawOff + (int rva - int va))
        match result with Some x -> x | None -> int rva

    let private findModuleBase (processId: uint32) (name: string) =
        let snapshot = Native.CreateToolhelp32Snapshot(Th32csSnapmodules ||| Th32csSnapmodule32, processId)
        if snapshot = 0n || snapshot = -1n then 0n
        else
            let buffer = Marshal.AllocHGlobal(ModuleEntrySize)
            try
                Marshal.WriteInt32(buffer, 0, ModuleEntrySize)
                let mutable found = 0n
                let mutable more = Native.Module32FirstW(snapshot, buffer)
                while more && found = 0n do
                    let modName = Marshal.PtrToStringUni(IntPtr.Add(buffer, ModNameOffset))
                    if not (isNull modName) && modName.Equals(name, StringComparison.OrdinalIgnoreCase) then
                        found <- Marshal.ReadIntPtr(IntPtr.Add(buffer, ModBaseAddrOffset))
                    else
                        more <- Native.Module32NextW(snapshot, buffer)
                found
            finally
                Marshal.FreeHGlobal(buffer)
                Native.CloseHandle(snapshot) |> ignore

    let private readRemote (proc: SafeProcessHandle) (address: nativeint) (size: int) =
        let buffer = Array.zeroCreate<byte> size
        let mutable bytesRead = 0n
        if not (Native.ReadProcessMemory(proc, address, buffer, nativeint size, &bytesRead)) then
            null
        else
            buffer

    let private writeRemote (proc: SafeProcessHandle) (address: nativeint) (data: byte[]) =
        Native.WriteProcessMemory(proc, address, data, nativeint data.Length, 0n)

    let private writeRemoteU64 (proc: SafeProcessHandle) (address: nativeint) (value: uint64) =
        let bytes = Array.zeroCreate<byte> 8
        writeU64 bytes 0 value
        writeRemote proc address bytes

    let private resolveExport (proc: SafeProcessHandle) (moduleBase: nativeint) (name: string) =
        let dos = readRemote proc moduleBase 64
        if isNull dos || readU16 dos 0 <> 0x5A4Dus then None
        else
            let ntOff = int (readU32 dos 0x3C)
            let ntSig = readRemote proc (IntPtr.Add(moduleBase, ntOff)) 4
            if isNull ntSig || readU32 ntSig 0 <> 0x00004550u then None
            else
                let coff = readRemote proc (IntPtr.Add(moduleBase, ntOff + 4)) 20
                if isNull coff then None
                else
                    let optSize = int (readU16 coff 16)
                    let opt = readRemote proc (IntPtr.Add(moduleBase, ntOff + 24)) optSize
                    if isNull opt then None
                    else
                        let exportRva = readU32 opt (112 + 0 * 8)
                        if exportRva = 0u then None
                        else
                            let exp = readRemote proc (IntPtr.Add(moduleBase, int exportRva)) 40
                            if isNull exp then None
                            else
                                let numNames = int (readU32 exp 24)
                                let numFuncs = int (readU32 exp 20)
                                let addrNames = readU32 exp 32
                                let addrFuncs = readU32 exp 28
                                let addrOrds = readU32 exp 36
                                let names = readRemote proc (IntPtr.Add(moduleBase, int addrNames)) (numNames * 4)
                                let funcs = readRemote proc (IntPtr.Add(moduleBase, int addrFuncs)) (numFuncs * 4)
                                let ords = readRemote proc (IntPtr.Add(moduleBase, int addrOrds)) (numNames * 2)
                                if isNull names || isNull funcs || isNull ords then None
                                else
                                    let mutable result = None
                                    let mutable i = 0
                                    while result.IsNone && i < numNames do
                                        let nameRva = readU32 names (i * 4)
                                        let buf = readRemote proc (IntPtr.Add(moduleBase, int nameRva)) 127
                                        if not (isNull buf) then
                                            let funcName =
                                                buf |> Array.tryFindIndex ((=) 0uy)
                                                |> Option.map (fun len -> Encoding.ASCII.GetString(buf, 0, len))
                                                |> Option.defaultValue ""
                                            if funcName = name then
                                                let ord = int (readU16 ords (i * 2))
                                                let funcRva = readU32 funcs (ord * 4)
                                                result <- Some(IntPtr.Add(moduleBase, int funcRva))
                                        i <- i + 1
                                    result

    let private buildContext (remoteBase: nativeint) (imageSize: uint32) (virtualFree: nativeint) (rtlExit: nativeint) (configBytes: byte[]) (ipcMappingHandle: uint64) =
        let buffer = Array.zeroCreate<byte> JvmCtxSize
        writeU32 buffer 0 JvmCtxMagic
        writeU32 buffer 4 JvmCtxVersion
        writeU32 buffer 8 (uint32 JvmCtxSize)
        writeU64 buffer 16 (uint64 (int64 remoteBase))
        writeU64 buffer 24 (uint64 imageSize)
        writeU64 buffer 32 (uint64 (int64 virtualFree))
        writeU64 buffer 40 (uint64 (int64 rtlExit))
        writeU64 buffer 48 ipcMappingHandle
        Array.Copy(configBytes, 0, buffer, JvmCtxConfigOffset, configBytes.Length)
        buffer

    let inject (payloadBytes: byte[]) (processId: uint32) (configBytes: byte[]) (ipcMapping: SafeFileHandle) =
        let access = ProcessVmOperation ||| ProcessVmRead ||| ProcessVmWrite ||| ProcessCreateThread ||| ProcessDupHandle ||| ProcessQueryInformation
        use proc = Native.OpenProcess(access, false, processId)
        if isNull proc || proc.IsInvalid then
            Error(win32Error "OpenProcess")
        else
            let ntOff = int (readU32 payloadBytes 0x3C)
            let imageBase = readU64 payloadBytes (ntOff + 24 + 24)
            let sizeOfImage = readU32 payloadBytes (ntOff + 24 + 56)
            let sizeOfHeaders = readU32 payloadBytes (ntOff + 24 + 60)
            let entryRva = readU32 payloadBytes (ntOff + 24 + 16)
            let sectionCount = int (readU16 payloadBytes (ntOff + 6))
            let optionalSize = int (readU16 payloadBytes (ntOff + 20))
            let sectionTable = ntOff + 24 + optionalSize
            let importRva = readU32 payloadBytes (ntOff + 24 + 112 + 1 * 8)
            let importSize = readU32 payloadBytes (ntOff + 24 + 112 + 1 * 8 + 4)
            let relocRva = readU32 payloadBytes (ntOff + 24 + 112 + 5 * 8)
            let relocSize = readU32 payloadBytes (ntOff + 24 + 112 + 5 * 8 + 4)

            let mutable remoteBase = 0n
            let mutable remoteCtx = 0n
            try
                remoteBase <- Native.VirtualAllocEx(proc, nativeint (int64 imageBase), uint64 sizeOfImage, MemCommit ||| MemReserve, PageExecuteReadWrite)
                if remoteBase = 0n then
                    remoteBase <- Native.VirtualAllocEx(proc, 0n, uint64 sizeOfImage, MemCommit ||| MemReserve, PageExecuteReadWrite)
                if remoteBase = 0n then raise (InvalidOperationException(win32Error "VirtualAllocEx"))

                if not (writeRemote proc remoteBase payloadBytes[.. int sizeOfHeaders - 1]) then
                    raise (InvalidOperationException(win32Error "WriteProcessMemory(headers)"))

                for i in 0 .. sectionCount - 1 do
                    let off = sectionTable + i * 40
                    let rawSize = readU32 payloadBytes (off + 16)
                    if rawSize > 0u then
                        let va = readU32 payloadBytes (off + 12)
                        let rawOff = readU32 payloadBytes (off + 20)
                        let sectionBytes = payloadBytes[int rawOff .. int rawOff + int rawSize - 1]
                        if not (writeRemote proc (IntPtr.Add(remoteBase, int va)) sectionBytes) then
                            raise (InvalidOperationException($"WriteProcessMemory(section {i})"))

                let kernelBase = findModuleBase processId "kernel32.dll"
                let ntdllBase = findModuleBase processId "ntdll.dll"
                if kernelBase = 0n || ntdllBase = 0n then
                    raise (InvalidOperationException "Failed to find kernel32 or ntdll in target")

                let virtualFree = resolveExport proc kernelBase "VirtualFree"
                let rtlExit = resolveExport proc ntdllBase "RtlExitUserThread"
                match virtualFree, rtlExit with
                | Some vf, Some rt ->
                    if importSize > 0u then
                        let importFileOff = rvaToFileOffset payloadBytes importRva
                        let mutable descOff = importFileOff
                        let mutable moreImports = true
                        let mutable dllNum = 0
                        while moreImports do
                            let nameRva = readU32 payloadBytes (descOff + 12)
                            if nameRva = 0u then
                                moreImports <- false
                            else
                                let nameFileOff = rvaToFileOffset payloadBytes nameRva
                                let moduleName =
                                    payloadBytes[nameFileOff .. nameFileOff + 127]
                                    |> Array.tryFindIndex ((=) 0uy)
                                    |> Option.map (fun len -> Encoding.ASCII.GetString(payloadBytes, nameFileOff, len))
                                    |> Option.defaultValue ""
                                if moduleName <> "" then
                                    let modBase = findModuleBase processId moduleName
                                    let modBase =
                                        if modBase = 0n && moduleName.Contains(".")
                                        then findModuleBase processId (moduleName.Split('.').[0])
                                        else modBase
                                    if modBase <> 0n then
                                        let oftRva = readU32 payloadBytes (descOff + 0)
                                        let iatRva = readU32 payloadBytes (descOff + 16)
                                        let thunkRva = if oftRva <> 0u then oftRva else iatRva
                                        let thunkFileOff = rvaToFileOffset payloadBytes thunkRva
                                        let mutable thunkIdx = 0
                                        let mutable moreThunks = true
                                        while moreThunks do
                                            let entry = readU64 payloadBytes (thunkFileOff + thunkIdx * 8)
                                            if entry = 0UL then
                                                moreThunks <- false
                                            else
                                                let resolved =
                                                    if entry &&& 0x8000000000000000UL <> 0UL then
                                                        None
                                                    else
                                                        let hintNameRva = uint32 entry
                                                        let hintFileOff = rvaToFileOffset payloadBytes hintNameRva
                                                        let funcName =
                                                            payloadBytes[hintFileOff + 2 .. hintFileOff + 129]
                                                            |> Array.tryFindIndex ((=) 0uy)
                                                            |> Option.map (fun len -> Encoding.ASCII.GetString(payloadBytes, hintFileOff + 2, len))
                                                            |> Option.defaultValue ""
                                                        if funcName = "" then None
                                                        else resolveExport proc modBase funcName
                                                match resolved with
                                                | None -> raise (InvalidOperationException $"Failed to resolve import in {moduleName}")
                                                | Some addr ->
                                                    let iatEntry = IntPtr.Add(IntPtr.Add(remoteBase, int iatRva), thunkIdx * 8)
                                                    writeRemoteU64 proc iatEntry (uint64 (int64 addr)) |> ignore
                                                thunkIdx <- thunkIdx + 1
                                descOff <- descOff + 20
                                dllNum <- dllNum + 1

                    let delta = int64 remoteBase - int64 imageBase
                    if relocSize > 0u && delta <> 0L then
                        let relocFileOff = rvaToFileOffset payloadBytes relocRva
                        let mutable offset = 0
                        while offset < int relocSize do
                            let blockVa = readU32 payloadBytes (relocFileOff + offset)
                            let blockSize = readU32 payloadBytes (relocFileOff + offset + 4)
                            if blockSize = 0u then offset <- int relocSize
                            else
                                let entryCount = int (blockSize - 8u) / 2
                                for k in 0 .. entryCount - 1 do
                                    let entry = readU16 payloadBytes (relocFileOff + offset + 8 + k * 2)
                                    let relocType = int (entry >>> 12)
                                    let relocOff = int (entry &&& 0x0FFFus)
                                    if relocType = 10 then
                                        let patchAddr = IntPtr.Add(IntPtr.Add(remoteBase, int blockVa), relocOff)
                                        let current = readRemote proc patchAddr 8
                                        if not (isNull current) then
                                            let value = uint64 (int64 (readU64 current 0) + delta)
                                            writeRemoteU64 proc patchAddr value |> ignore
                                offset <- offset + int blockSize

                    Native.FlushInstructionCache(proc, remoteBase, nativeint sizeOfImage) |> ignore

                    (* Duplicate the anonymous IPC mapping handle into the target - no name strings *)
                    let mutable remoteMappingHandle = 0n
                    use currentProc = Native.GetCurrentProcess()
                    if not (Native.DuplicateHandle(currentProc, ipcMapping, proc, &remoteMappingHandle, 0u, false, 0x2u (* DUPLICATE_SAME_ACCESS *))) then
                        raise (InvalidOperationException(win32Error "DuplicateHandle(IPC mapping)"))

                    let ctxBytes = buildContext remoteBase sizeOfImage vf rt configBytes (uint64 (int64 remoteMappingHandle))
                    remoteCtx <- Native.VirtualAllocEx(proc, 0n, uint64 JvmCtxSize, MemCommit ||| MemReserve, PageReadWrite)
                    if remoteCtx = 0n then raise (InvalidOperationException(win32Error "VirtualAllocEx(context)"))
                    if not (writeRemote proc remoteCtx ctxBytes) then
                        raise (InvalidOperationException(win32Error "WriteProcessMemory(context)"))

                    let entryAddr = IntPtr.Add(remoteBase, int entryRva)
                    let mutable threadId = 0u
                    (* Create with StartAddress = RtlExitUserThread (legitimate ntdll
                     * function) and CREATE_SUSPENDED. The ETHREAD records
                     * StartAddress = RtlExitUserThread, not the DLL entry. *)
                    let thread = Native.CreateRemoteThread(proc, 0n, 0x400000u, rt, remoteCtx, 0x4u, &threadId)
                    if isNull thread || thread.IsInvalid then
                        raise (InvalidOperationException(win32Error "CreateRemoteThread"))
                    (* Redirect RCX from RtlExitUserThread to the DLL entry.
                     * RtlUserThreadStart calls the function in RCX with the
                     * parameter in RDX (which is already remoteCtx). *)
                    (* AMD64 CONTEXT requires 16-byte alignment — a managed
                     * byte[] is NOT guaranteed 16-byte aligned on the GC
                     * heap, which causes GetThreadContext to fail with
                     * error 998.  Use AllocHGlobal + manual alignment. *)
                    let ctxRaw = Marshal.AllocHGlobal(1232 + 16)
                    try
                        let ctxAligned = ((ctxRaw + 15n) &&& ~~~15n)
                        Marshal.WriteInt32(ctxAligned + 0x30n, 0x100007)
                        let mutable ctxOk = false
                        let mutable tries = 0
                        while not ctxOk && tries < 10 do
                            ctxOk <- Native.GetThreadContext(thread, ctxAligned)
                            if not ctxOk then Thread.Sleep(10)
                            tries <- tries + 1
                        if not ctxOk then
                            raise (InvalidOperationException(win32Error "GetThreadContext"))
                        Marshal.WriteInt64(ctxAligned + 0x80n, int64 entryAddr)
                        if not (Native.SetThreadContext(thread, ctxAligned)) then
                            raise (InvalidOperationException(win32Error "SetThreadContext"))
                        Native.ResumeThread(thread) |> ignore
                    finally
                        Marshal.FreeHGlobal(ctxRaw)
                    thread.Dispose()
                    Thread.Sleep(500)
                    Ok remoteBase
                | _ -> raise (InvalidOperationException "Failed to resolve VirtualFree or RtlExitUserThread")
            with
            | error ->
                if remoteCtx <> 0n then Native.VirtualFreeEx(proc, remoteCtx, 0UL, MemRelease) |> ignore
                if remoteBase <> 0n then Native.VirtualFreeEx(proc, remoteBase, 0UL, MemRelease) |> ignore
                Error error.Message

let private byteArrayEqual (a: byte array) (b: byte array) =
    if isNull a || isNull b then false
    elif a.Length <> b.Length then false
    else
        let mutable i = 0
        let mutable equal = true
        while equal && i < a.Length do
            if a[i] <> b[i] then equal <- false
            i <- i + 1
        equal

let private verifyRelease
    (metadataBytes: byte array)
    (payloadBytes: byte array)
    (publicKey: RSA)
    (constraints: ReleaseMetadata.MetadataConstraints)
    : Result<ReleaseMetadata.Metadata * Pe.Image, string> =
    try
        let metadata = ReleaseMetadata.deserialize metadataBytes
        let errors = ReleaseMetadata.validate constraints metadata
        if not errors.IsEmpty then
            raise (InvalidDataException(errors |> String.concat "; "))
        if uint64 payloadBytes.Length <> metadata.PayloadLength then
            raise (InvalidDataException $"Payload length {payloadBytes.Length} does not match metadata {metadata.PayloadLength}")
        let digest = SignatureVerification.computeSha256 payloadBytes
        if not (byteArrayEqual digest metadata.Sha256) then
            raise (InvalidDataException "SHA-256 digest does not match metadata")
        if not (SignatureVerification.verifySignature payloadBytes metadata.Signature publicKey) then
            raise (InvalidDataException "Signature verification failed")
        let image = Pe.inspect payloadBytes
        Ok(metadata, image)
    with
    | :? InvalidDataException as error -> Error error.Message
    | :? ArgumentException as error -> Error error.Message
    | :? OverflowException as error -> Error error.Message

let private defaultConstraints () : ReleaseMetadata.MetadataConstraints = {
    MinimumLoaderVersion = Loader.MinimumLoaderVersion
    ExpectedAbiVersion = Configuration.Version
    ExpectedArchitecture = ReleaseMetadata.Architecture.Amd64
    NowUnixSeconds = uint64 (DateTimeOffset.UtcNow.ToUnixTimeSeconds())
}

let private printRelease (metadata: ReleaseMetadata.Metadata) (image: Pe.Image) =
    printfn "Verification succeeded"
    printfn "  Loader version:   %u" metadata.LoaderVersion
    printfn "  Payload version:  %u" metadata.PayloadVersion
    printfn "  ABI version:      %u" metadata.AbiVersion
    printfn "  Architecture:     %A" metadata.Architecture
    printfn "  Payload length:   %u" metadata.PayloadLength
    printfn "  SHA-256:          %s" (Convert.ToHexString(metadata.Sha256).ToLowerInvariant())
    printfn "  Key ID:           %s" (Convert.ToHexString(metadata.SigningKeyId).ToLowerInvariant())
    printfn "  Expiration:       %u" metadata.ExpirationUnixSeconds
    printfn "  Image base:       0x%016X" image.ImageBase
    printfn "  Image size:       %u bytes" image.SizeOfImage
    printfn "  Entry point RVA:  0x%08X" image.EntryPointRva
    printfn "  Sections:         %d" image.Sections.Length

module WinFormsShell =
    module private ShellNative =
        [<DllImport("user32.dll")>]
        extern int16 GetAsyncKeyState(int virtualKey)

    let private VK_CONTROL = 0x11
    let private VK_SHIFT = 0x10
    let private VK_INSERT = 0x2D

    let private vkName (vk: int) =
        match vk with
        | 0 -> "None"
        | 0x01 -> "LButton"
        | 0x02 -> "RButton"
        | 0x04 -> "MMouse"
        | 0x05 -> "X1Mouse"
        | 0x06 -> "X2Mouse"
        | 0x08 -> "Backspace"
        | 0x09 -> "Tab"
        | 0x0D -> "Enter"
        | 0x10 -> "Shift"
        | 0x11 -> "Ctrl"
        | 0x12 -> "Alt"
        | 0x14 -> "CapsLock"
        | 0x1B -> "Esc"
        | 0x20 -> "Space"
        | 0x21 -> "PgUp"
        | 0x22 -> "PgDn"
        | 0x23 -> "End"
        | 0x24 -> "Home"
        | 0x25 -> "Left"
        | 0x26 -> "Up"
        | 0x27 -> "Right"
        | 0x28 -> "Down"
        | 0x2D -> "Insert"
        | 0x2E -> "Delete"
        | 0x30 | 0x60 -> "0"
        | 0x31 | 0x61 -> "1"
        | 0x32 | 0x62 -> "2"
        | 0x33 | 0x63 -> "3"
        | 0x34 | 0x64 -> "4"
        | 0x35 | 0x65 -> "5"
        | 0x36 | 0x66 -> "6"
        | 0x37 | 0x67 -> "7"
        | 0x38 | 0x68 -> "8"
        | 0x39 | 0x69 -> "9"
        | k when k >= 0x41 && k <= 0x5A -> string (char k)
        | 0x70 -> "F1"
        | 0x71 -> "F2"
        | 0x72 -> "F3"
        | 0x73 -> "F4"
        | 0x74 -> "F5"
        | 0x75 -> "F6"
        | 0x76 -> "F7"
        | 0x77 -> "F8"
        | 0x78 -> "F9"
        | 0x79 -> "F10"
        | 0x7A -> "F11"
        | 0x7B -> "F12"
        | 0xA0 -> "LShift"
        | 0xA1 -> "RShift"
        | 0xA2 -> "LCtrl"
        | 0xA3 -> "RCtrl"
        | 0xBA -> ";"
        | 0xBB -> "="
        | 0xBC -> ","
        | 0xBD -> "-"
        | 0xBE -> "."
        | 0xBF -> "/"
        | 0xC0 -> "`"
        | 0xDB -> "["
        | 0xDC -> "\\"
        | 0xDD -> "]"
        | 0xDE -> "'"
        | _ -> $"Key0x{vk:X2}"


    type private CandidateItem(target: TargetDiscovery.Target) =
        member _.Target = target
        override _.ToString() =
            let title = if String.IsNullOrWhiteSpace(target.WindowTitle) then "Untitled window" else target.WindowTitle
            $"{title}  |  PID {target.ProcessId}  |  {target.WindowClass}"

    let private disposeTargets (targets: TargetDiscovery.Target list) =
        targets |> List.iter (fun target -> (target :> IDisposable).Dispose())

    let private runWindow smokeTest =
        let state = LoaderState.Controller()
        let mutable targets: TargetDiscovery.Target list = []
        let mutable operation: CancellationTokenSource option = None
        let mutable ipcSession: IpcAbi.Session option = None
        let mutable sessionTarget: TargetDiscovery.Target option = None
        let mutable closeAfterShutdown = false
        let mutable lastMonitorMessage = ""

        (* ---- Nexus palette ---- *)
        let cBg        = Color.FromArgb(39, 39, 42)
        let cPanel     = Color.FromArgb(45, 45, 49)
        let cCard      = Color.FromArgb(53, 53, 58)
        let cCardHov   = Color.FromArgb(61, 61, 66)
        let cBorder    = Color.FromArgb(69, 69, 74)
        let cAccent    = Color.FromArgb(72, 196, 150)
        let cAccentHov = Color.FromArgb(91, 214, 168)
        let cText      = Color.FromArgb(246, 246, 247)
        let cTextDim   = Color.FromArgb(180, 180, 184)
        let cTextMut   = Color.FromArgb(125, 125, 132)
        let cGreen     = cAccent
        let cRed       = Color.FromArgb(242, 105, 105)

        let fontBrand  = new Font("Segoe UI Semibold", 10.0f)
        let fontTitle  = new Font("Segoe UI Semibold", 12.0f)
        let fontBody   = new Font("Segoe UI", 9.0f)
        let fontBodyS  = new Font("Segoe UI", 8.5f)

        let form = new Form()
        form.Text <- "System Helper"
        form.StartPosition <- FormStartPosition.CenterScreen
        form.MinimumSize <- Size(760, 520)
        form.ClientSize <- Size(1024, 640)
        form.Font <- fontBody
        form.BackColor <- cBg
        form.ForeColor <- cText
        form.FormBorderStyle <- FormBorderStyle.Sizable
        form.MaximizeBox <- true

        (* ---- Header ---- *)
        let header = new Panel(Dock = DockStyle.Top, Height = 44, BackColor = cBg)
        header.Padding <- System.Windows.Forms.Padding(20, 0, 20, 0)
        let title = new Label(Text = "NEXUS", Font = fontBrand, ForeColor = cText, AutoSize = true, Location = Point(20, 14))
        let subtitle = new Label(Text = "SYSTEM HELPER", Font = fontBodyS, ForeColor = cTextMut, AutoSize = true, Location = Point(88, 15))
        let headerLine = new Panel(Dock = DockStyle.Bottom, Height = 1, BackColor = cBorder)
        header.Controls.Add(title)
        header.Controls.Add(subtitle)
        header.Controls.Add(headerLine)

        (* ---- Content ---- *)
        let content = new TableLayoutPanel(Dock = DockStyle.Fill, BackColor = cBg, Padding = System.Windows.Forms.Padding(16, 10, 16, 10), ColumnCount = 1, RowCount = 4)
        content.RowStyles.Add(RowStyle(SizeType.Absolute, 58.0f)) |> ignore
        content.RowStyles.Add(RowStyle(SizeType.Absolute, 46.0f)) |> ignore
        content.RowStyles.Add(RowStyle(SizeType.Percent, 100.0f)) |> ignore
        content.RowStyles.Add(RowStyle(SizeType.Absolute, 36.0f)) |> ignore

        (* ---- Target info card ---- *)
        let targetCard = new Panel(Dock = DockStyle.Fill, BackColor = cPanel, Padding = System.Windows.Forms.Padding(16, 9, 16, 9))
        let targetLabel = new Label(Text = "HOME", Font = fontTitle, ForeColor = cText, AutoSize = true, Location = Point(16, 9))
        let targetDetails = new Label(Text = "Scanning for Minecraft...", Font = fontBodyS, ForeColor = cTextMut, AutoEllipsis = true, Location = Point(16, 31), Anchor = (AnchorStyles.Left ||| AnchorStyles.Right ||| AnchorStyles.Top), Width = 700)
        targetCard.Controls.Add(targetLabel)
        targetCard.Controls.Add(targetDetails)

        (* ---- Action bar ---- *)
        let actionBar = new FlowLayoutPanel(Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, BackColor = cBg, Padding = System.Windows.Forms.Padding(0, 7, 0, 4))
        let stopButton = new Button(Text = "Stop runtime", Width = 128, Height = 32, Enabled = false, BackColor = cCard, ForeColor = cTextDim, FlatStyle = FlatStyle.Flat, Font = fontBody)
        stopButton.FlatAppearance.BorderSize <- 1
        stopButton.FlatAppearance.BorderColor <- cBorder
        let cancelButton = new Button(Text = "Cancel", Width = 82, Height = 32, Enabled = false, BackColor = cCard, ForeColor = cTextDim, FlatStyle = FlatStyle.Flat, Font = fontBody)
        cancelButton.FlatAppearance.BorderSize <- 1
        cancelButton.FlatAppearance.BorderColor <- cBorder
        actionBar.Controls.Add(stopButton)
        actionBar.Controls.Add(cancelButton)

        (* ---- Settings panel (no tabs, no activity log) ---- *)
        let settingsRoot = new TableLayoutPanel(Dock = DockStyle.Fill, BackColor = cBg, Padding = System.Windows.Forms.Padding(0, 4, 0, 4), ColumnCount = 2, RowCount = 1)
        settingsRoot.ColumnStyles.Add(ColumnStyle(SizeType.Percent, 38.0f)) |> ignore
        settingsRoot.ColumnStyles.Add(ColumnStyle(SizeType.Percent, 62.0f)) |> ignore
        settingsRoot.RowStyles.Add(RowStyle(SizeType.Percent, 100.0f)) |> ignore

        let darkGroupBox (text: string) =
            let g = new GroupBox(Text = text, Dock = DockStyle.Fill, BackColor = cPanel, ForeColor = cTextDim, Font = fontBody, Padding = System.Windows.Forms.Padding(14, 12, 14, 12))
            g

        let settingGrid (g: GroupBox) =
            let grid = new TableLayoutPanel(Dock = DockStyle.Fill, BackColor = cPanel, ColumnCount = 2, AutoScroll = true, Padding = System.Windows.Forms.Padding(4, 8, 4, 4))
            grid.ColumnStyles.Add(ColumnStyle(SizeType.Percent, 58.0f)) |> ignore
            grid.ColumnStyles.Add(ColumnStyle(SizeType.Percent, 42.0f)) |> ignore
            g.Controls.Add(grid)
            grid

        let styleLabel (l: Label) = l.ForeColor <- cTextDim; l.Font <- fontBodyS
        let styleCheckBox (c: CheckBox) = c.ForeColor <- cText; c.Font <- fontBodyS
        let styleNumeric (n: NumericUpDown) = n.BackColor <- cCard; n.ForeColor <- cText; n.Font <- fontBodyS; n.BorderStyle <- BorderStyle.FixedSingle
        let styleCombo (b: ComboBox) = b.BackColor <- cCard; b.ForeColor <- cText; b.Font <- fontBodyS; b.FlatStyle <- FlatStyle.Flat
        let styleTextBox (t: TextBox) = t.BackColor <- cCard; t.ForeColor <- cText; t.Font <- fontBodyS; t.BorderStyle <- BorderStyle.FixedSingle

        let addSetting (grid: TableLayoutPanel) labelText (control: Control) =
            let row = grid.RowCount
            grid.RowCount <- row + 1
            grid.RowStyles.Add(RowStyle(SizeType.Absolute, 36.0f)) |> ignore
            let lbl = new Label(Text = labelText, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft)
            styleLabel lbl
            grid.Controls.Add(lbl, 0, row)
            control.Dock <- DockStyle.Fill
            match control with
            | :? CheckBox as c -> styleCheckBox c
            | :? NumericUpDown as n -> styleNumeric n
            | :? ComboBox as b -> styleCombo b
            | :? TextBox as t -> styleTextBox t
            | _ -> ()
            grid.Controls.Add(control, 1, row)

        let numeric minimum maximum value =
            let n = new NumericUpDown(Minimum = decimal minimum, Maximum = decimal maximum, Value = decimal value)
            styleNumeric n
            n

        let modeBox selected =
            let box = new ComboBox(DropDownStyle = ComboBoxStyle.DropDownList)
            styleCombo box
            box.Items.Add("Normal") |> ignore
            box.Items.Add("Extra") |> ignore
            box.Items.Add("Extra Plus") |> ignore
            box.SelectedIndex <- int selected
            box

        let leftGroup = darkGroupBox "AutoClicker settings"
        let leftGrid = settingGrid leftGroup
        let leftEnabled = new CheckBox(Checked = Configuration.defaults.Left.Enabled)
        let leftMinimum = numeric 1 20 Configuration.defaults.Left.MinimumCps
        let leftMaximum = numeric 1 20 Configuration.defaults.Left.MaximumCps
        let leftMode = modeBox Configuration.defaults.Left.Randomization
        let leftHold = new CheckBox(Checked = Configuration.defaults.Left.HoldToClick)
        let leftTrigger = new CheckBox(Checked = Configuration.defaults.LeftTriggerMode)
        let leftBreak = new CheckBox(Checked = Configuration.defaults.LeftBreakBlocks)
        let breakMinimum = numeric 0 2000 Configuration.defaults.LeftBreakDelayMinimum
        let breakMaximum = numeric 0 2000 Configuration.defaults.LeftBreakDelayMaximum
        let breakWhitelist = new CheckBox(Checked = Configuration.defaults.LeftBreakWhitelist)
        addSetting leftGrid "Min CPS" leftMinimum
        addSetting leftGrid "Max CPS" leftMaximum
        addSetting leftGrid "Randomization" leftMode
        addSetting leftGrid "Hold to click" leftHold
        addSetting leftGrid "Trigger mode" leftTrigger
        addSetting leftGrid "Break blocks" leftBreak
        addSetting leftGrid "Break min (ms)" breakMinimum
        addSetting leftGrid "Break max (ms)" breakMaximum
        addSetting leftGrid "Tool whitelist" breakWhitelist
        let leftHotkeyBtn = new Button(Text = "None", Width = 120, FlatStyle = FlatStyle.Flat, BackColor = cCard, ForeColor = cText, Font = fontBodyS)
        leftHotkeyBtn.FlatAppearance.BorderColor <- cBorder
        addSetting leftGrid "Toggle hotkey" leftHotkeyBtn

        let rightGroup = darkGroupBox "RightClicker settings"
        let rightGrid = settingGrid rightGroup
        let rightEnabled = new CheckBox(Checked = Configuration.defaults.Right.Enabled)
        let rightMinimum = numeric 1 20 Configuration.defaults.Right.MinimumCps
        let rightMaximum = numeric 1 20 Configuration.defaults.Right.MaximumCps
        let rightMode = modeBox Configuration.defaults.Right.Randomization
        let rightHold = new CheckBox(Checked = Configuration.defaults.Right.HoldToClick)
        let rightDelay = numeric 0 1000 Configuration.defaults.RightStartDelayMillis
        let rightWhitelistEnabled = new CheckBox(Checked = Configuration.defaults.RightUseItemWhitelist)
        let rightWhitelist = new TextBox(Text = String.concat ", " Configuration.defaults.RightWhitelist)
        addSetting rightGrid "Min CPS" rightMinimum
        addSetting rightGrid "Max CPS" rightMaximum
        addSetting rightGrid "Randomization" rightMode
        addSetting rightGrid "Hold to click" rightHold
        addSetting rightGrid "Start delay (ms)" rightDelay
        addSetting rightGrid "Item whitelist" rightWhitelistEnabled
        addSetting rightGrid "Items (comma sep)" rightWhitelist
        let rightHotkeyBtn = new Button(Text = "None", Width = 120, FlatStyle = FlatStyle.Flat, BackColor = cCard, ForeColor = cText, Font = fontBodyS)
        rightHotkeyBtn.FlatAppearance.BorderColor <- cBorder
        addSetting rightGrid "Toggle hotkey" rightHotkeyBtn

        let hitFlickGroup = darkGroupBox "HitFlick settings"
        let hitFlickGrid = settingGrid hitFlickGroup
        let hitFlickEnabled = new CheckBox(Checked = Configuration.defaults.HitFlickEnabled)
        addSetting hitFlickGrid "Enabled" hitFlickEnabled
        let hitFlickHotkeyBtn = new Button(Text = "CapsLock", Width = 120, FlatStyle = FlatStyle.Flat, BackColor = cCard, ForeColor = cText, Font = fontBodyS)
        hitFlickHotkeyBtn.FlatAppearance.BorderColor <- cBorder
        addSetting hitFlickGrid "Toggle hotkey" hitFlickHotkeyBtn

        let moduleList = new TableLayoutPanel(Dock = DockStyle.Fill, BackColor = cBg, Padding = System.Windows.Forms.Padding(0, 0, 12, 0), ColumnCount = 1, RowCount = 4)
        moduleList.RowStyles.Add(RowStyle(SizeType.Absolute, 82.0f)) |> ignore
        moduleList.RowStyles.Add(RowStyle(SizeType.Absolute, 82.0f)) |> ignore
        moduleList.RowStyles.Add(RowStyle(SizeType.Percent, 100.0f)) |> ignore

        let moduleRow name summary (toggle: CheckBox) =
            let panel = new Panel(Dock = DockStyle.Fill, BackColor = cCard, Margin = System.Windows.Forms.Padding(0, 0, 0, 8), Cursor = Cursors.Hand)
            let nameLabel = new Label(Text = name, Font = fontTitle, ForeColor = cText, AutoSize = true, Location = Point(16, 13), Cursor = Cursors.Hand)
            let summaryLabel = new Label(Text = summary, Font = fontBodyS, ForeColor = cTextMut, AutoEllipsis = true, Location = Point(16, 42), Anchor = (AnchorStyles.Left ||| AnchorStyles.Right ||| AnchorStyles.Top), Width = 235, Cursor = Cursors.Hand)
            toggle.Appearance <- Appearance.Button
            toggle.AutoSize <- false
            toggle.Size <- Size(50, 26)
            toggle.Location <- Point(panel.Width - 66, 24)
            toggle.Anchor <- AnchorStyles.Top ||| AnchorStyles.Right
            toggle.FlatStyle <- FlatStyle.Flat
            toggle.FlatAppearance.BorderSize <- 0
            toggle.TextAlign <- ContentAlignment.MiddleCenter
            toggle.Font <- fontBodyS
            let refreshToggle () =
                toggle.Text <- if toggle.Checked then "ON" else "OFF"
                toggle.BackColor <- if toggle.Checked then cAccent else cCardHov
                toggle.ForeColor <- if toggle.Checked then cBg else cTextDim
            toggle.CheckedChanged.Add(fun _ -> refreshToggle())
            refreshToggle()
            panel.Controls.Add(nameLabel)
            panel.Controls.Add(summaryLabel)
            panel.Controls.Add(toggle)
            panel, nameLabel, summaryLabel

        let leftRow, leftNameLabel, leftSummary = moduleRow "AutoClicker" "12-15 CPS, Extra, hold to click" leftEnabled
        let rightRow, rightNameLabel, rightSummary = moduleRow "RightClicker" "8-11 CPS, Extra, hold to click" rightEnabled
        let flickRow, flickNameLabel, flickSummary = moduleRow "HitFlick" "Random 45-135 degree KB displacement" hitFlickEnabled
        let settingsPane = new Panel(Dock = DockStyle.Fill, BackColor = cPanel, Padding = System.Windows.Forms.Padding(8))
        settingsPane.Controls.Add(hitFlickGroup)
        settingsPane.Controls.Add(rightGroup)
        settingsPane.Controls.Add(leftGroup)
        leftGroup.BringToFront()
        rightGroup.Visible <- false
        hitFlickGroup.Visible <- false

        let selectModule (which: int) =
            leftGroup.Visible <- (which = 0)
            rightGroup.Visible <- (which = 1)
            hitFlickGroup.Visible <- (which = 2)
            if which = 0 then leftGroup.BringToFront()
            elif which = 1 then rightGroup.BringToFront()
            else hitFlickGroup.BringToFront()
            leftRow.BackColor <- if which = 0 then cCardHov else cCard
            rightRow.BackColor <- if which = 1 then cCardHov else cCard
            flickRow.BackColor <- if which = 2 then cCardHov else cCard
            leftNameLabel.ForeColor <- if which = 0 then cAccent else cText
            rightNameLabel.ForeColor <- if which = 1 then cAccent else cText
            flickNameLabel.ForeColor <- if which = 2 then cAccent else cText

        let bindSelect (panel: Panel) (label1: Label) (label2: Label) which =
            panel.Click.Add(fun _ -> selectModule which)
            label1.Click.Add(fun _ -> selectModule which)
            label2.Click.Add(fun _ -> selectModule which)

        bindSelect leftRow leftNameLabel leftSummary 0
        bindSelect rightRow rightNameLabel rightSummary 1
        bindSelect flickRow flickNameLabel flickSummary 2
        selectModule 0

        let updateSummaries () =
            let modeText (box: ComboBox) = if box.SelectedItem = null then "Normal" else string box.SelectedItem
            let enabledText value text = if value then $", {text}" else ""
            let leftHoldText = enabledText leftHold.Checked "hold"
            let leftTriggerText = enabledText leftTrigger.Checked "trigger"
            let rightHoldText = enabledText rightHold.Checked "hold"
            let rightWhitelistText = enabledText rightWhitelistEnabled.Checked "whitelist"
            leftSummary.Text <- $"{int leftMinimum.Value}-{int leftMaximum.Value} CPS, {modeText leftMode}{leftHoldText}{leftTriggerText}"
            rightSummary.Text <- $"{int rightMinimum.Value}-{int rightMaximum.Value} CPS, {modeText rightMode}{rightHoldText}{rightWhitelistText}"

        [| leftMinimum :> Control; leftMaximum :> Control; leftMode :> Control; leftHold :> Control; leftTrigger :> Control
           rightMinimum :> Control; rightMaximum :> Control; rightMode :> Control; rightHold :> Control; rightWhitelistEnabled :> Control |]
        |> Array.iter (fun control ->
            match control with
            | :? NumericUpDown as number -> number.ValueChanged.Add(fun _ -> updateSummaries())
            | :? ComboBox as box -> box.SelectedIndexChanged.Add(fun _ -> updateSummaries())
            | :? CheckBox as box -> box.CheckedChanged.Add(fun _ -> updateSummaries())
            | _ -> ())
        updateSummaries()

        moduleList.Controls.Add(leftRow, 0, 0)
        moduleList.Controls.Add(rightRow, 0, 1)
        moduleList.Controls.Add(flickRow, 0, 2)
        settingsRoot.Controls.Add(moduleList, 0, 0)
        settingsRoot.Controls.Add(settingsPane, 1, 0)

        (* ---- Footer ---- *)
        let footer = new Panel(Dock = DockStyle.Fill, BackColor = cBg)
        let stateLabel = new Label(Text = "Idle", AutoSize = true, Location = Point(4, 9), Font = fontBodyS, ForeColor = cTextDim)
        let runtimeLabel = new Label(Text = "offline", AutoSize = true, ForeColor = cTextMut, Font = fontBodyS, Location = Point(160, 9))
        let sdkLabel = new Label(Text = "v1.0", AutoSize = true, ForeColor = cTextMut, Font = fontBodyS, Anchor = (AnchorStyles.Top ||| AnchorStyles.Right))
        footer.Controls.Add(stateLabel)
        footer.Controls.Add(runtimeLabel)
        footer.Controls.Add(sdkLabel)
        footer.Resize.Add(fun _ -> sdkLabel.Location <- Point(footer.ClientSize.Width - sdkLabel.Width - 4, 9))

        content.Controls.Add(targetCard, 0, 0)
        content.Controls.Add(actionBar, 0, 1)
        content.Controls.Add(settingsRoot, 0, 2)
        content.Controls.Add(footer, 0, 3)
        form.Controls.Add(content)
        form.Controls.Add(header)

        let appendActivity (_message: string) = ()

        let setState next =
            state.Transition(next)
            stateLabel.Text <- LoaderState.describe next

        let setBusy busy =
            let runtimeActive = ipcSession.IsSome
            cancelButton.Enabled <- busy
            stopButton.Enabled <- not busy && runtimeActive

        let dispatch (action: unit -> unit) =
            if not form.IsDisposed && form.IsHandleCreated then
                form.BeginInvoke(Action(action)) |> ignore

        let finishOperation () =
            operation |> Option.iter (fun value -> value.Dispose())
            operation <- None
            setBusy false

        let failOperation message =
            setState (LoaderState.Failed message)
            appendActivity $"ERROR: {message}"
            finishOperation()

        let buildConfiguration () =
            let mode (box: ComboBox) = enum<Configuration.RandomizationMode>(box.SelectedIndex)
            let whitelist =
                rightWhitelist.Text.Split(',', StringSplitOptions.RemoveEmptyEntries ||| StringSplitOptions.TrimEntries)
                |> Array.toList
            let snapshot = {
                Configuration.Version = Configuration.Version
                Configuration.Left = {
                    Enabled = leftEnabled.Checked
                    MinimumCps = int leftMinimum.Value
                    MaximumCps = int leftMaximum.Value
                    Randomization = mode leftMode
                    HoldToClick = leftHold.Checked
                }
                Configuration.LeftTriggerMode = leftTrigger.Checked
                Configuration.LeftBreakBlocks = leftBreak.Checked
                Configuration.LeftBreakDelayMinimum = int breakMinimum.Value
                Configuration.LeftBreakDelayMaximum = int breakMaximum.Value
                Configuration.LeftBreakWhitelist = breakWhitelist.Checked
                Configuration.Right = {
                    Enabled = rightEnabled.Checked
                    MinimumCps = int rightMinimum.Value
                    MaximumCps = int rightMaximum.Value
                    Randomization = mode rightMode
                    HoldToClick = rightHold.Checked
                }
                Configuration.RightStartDelayMillis = int rightDelay.Value
                Configuration.RightUseItemWhitelist = rightWhitelistEnabled.Checked
                Configuration.RightWhitelist = whitelist
                Configuration.HitFlickEnabled = hitFlickEnabled.Checked
            }
            let errors = Configuration.validate snapshot
            if errors.IsEmpty then Ok snapshot else Error errors

        let disposeSession () =
            match ipcSession with
            | Some session ->
                (session :> IDisposable).Dispose()
                ipcSession <- None
                sessionTarget <- None
            | None -> ()
            stopButton.Enabled <- false
            runtimeLabel.Text <- "offline"

        let publishConfig () =
            match ipcSession, buildConfiguration() with
            | Some session, Ok snapshot ->
                try
                    let generation = session.Publish(snapshot)
                    session.SetLoaderState(IpcAbi.LifecycleState.Ready, 0)
                    runtimeLabel.Text <- $"{IpcAbi.LifecycleState.Ready} | gen {generation}"
                with _ -> ()
            | _ -> ()

        let mutable requestShutdown: bool -> unit = ignore

        let cleanupAfterShutdown acknowledged =
            let session = ipcSession
            session |> Option.iter (fun value ->
                try value.SetLoaderState((if acknowledged then IpcAbi.LifecycleState.Stopped else IpcAbi.LifecycleState.Failed), (if acknowledged then 0 else 408))
                with _ -> ())
            disposeSession()
            if acknowledged then
                setState LoaderState.Stopped
                appendActivity "Runtime stopped"
            else
                setState (LoaderState.Failed "Shutdown timed out")
                appendActivity "ERROR: shutdown timed out"
            finishOperation()
            if closeAfterShutdown && not form.IsDisposed then
                closeAfterShutdown <- false
                form.Close()

        requestShutdown <- fun closeWhenDone ->
            closeAfterShutdown <- closeAfterShutdown || closeWhenDone
            match ipcSession with
            | None ->
                if closeAfterShutdown && not form.IsDisposed then
                    closeAfterShutdown <- false
                    form.Close()
            | Some session when state.State <> LoaderState.Stopping ->
                if state.TryTransition(LoaderState.Stopping) then
                    stateLabel.Text <- LoaderState.describe LoaderState.Stopping
                    setBusy true
                    let cancellation = new CancellationTokenSource()
                    operation <- Some cancellation
                    try
                        session.SetLoaderState(IpcAbi.LifecycleState.Stopping, 0)
                        session.RequestStop()
                        appendActivity "Stopping..."
                        Task.Run((fun () -> session.WaitForStopAcknowledgement(TimeSpan.FromSeconds(3.0))), cancellation.Token)
                            .ContinueWith(fun (completed: Task<bool>) ->
                                dispatch (fun () ->
                                    if completed.IsCanceled then cleanupAfterShutdown false
                                    elif completed.IsFaulted then
                                        appendActivity $"ERROR: {completed.Exception.GetBaseException().Message}"
                                        cleanupAfterShutdown false
                                    else cleanupAfterShutdown completed.Result))
                        |> ignore
                    with error ->
                        appendActivity $"ERROR: {error.Message}"
                        cleanupAfterShutdown false
            | Some _ -> ()

        (* ---- Auto-inject flow: discover -> download -> verify -> inject ---- *)
        let releaseEndpoint = "https://github.com/tejugenz-ops/gg/releases/download/v1"

        let startInjection (selectedTarget: TargetDiscovery.Target) =
            if state.TryTransition(LoaderState.DownloadingPayload) then
                stateLabel.Text <- LoaderState.describe LoaderState.DownloadingPayload
                setBusy true
                let cancellation = new CancellationTokenSource()
                operation <- Some cancellation
                appendActivity "Acquiring payload..."
                Task.Run((fun () ->
                    let initialErrors = TargetDiscovery.revalidate selectedTarget
                    if not initialErrors.IsEmpty then Error(initialErrors |> String.concat "; ")
                    else
                        use publicKey = PinnedKey.load()
                        match Acquisition.download (Acquisition.defaultConfig releaseEndpoint) cancellation.Token with
                        | Error message -> Error message
                        | Ok(metadataBytes, payloadBytes) ->
                            cancellation.Token.ThrowIfCancellationRequested()
                            let errors = TargetDiscovery.revalidate selectedTarget
                            if not errors.IsEmpty then Error(errors |> String.concat "; ")
                            else verifyRelease metadataBytes payloadBytes publicKey (defaultConstraints())
                                 |> Result.map (fun (metadata, image) -> (metadata, image, payloadBytes))), cancellation.Token)
                    .ContinueWith(fun (completed: Task<Result<ReleaseMetadata.Metadata * Pe.Image * byte[], string>>) ->
                        dispatch (fun () ->
                            if completed.IsCanceled || cancellation.IsCancellationRequested then
                                appendActivity "Cancelled"
                                setState LoaderState.Idle
                                finishOperation()
                            elif completed.IsFaulted then
                                failOperation (completed.Exception.GetBaseException().Message)
                            else
                                setState LoaderState.VerifyingPayload
                                match completed.Result with
                                | Error message -> failOperation message
                                | Ok(metadata, image, payloadBytes) ->
                                    appendActivity "Payload verified"
                                    sdkLabel.Text <- $"V 1.{metadata.PayloadVersion}"
                                    setState LoaderState.PreparingIpc
                                    match buildConfiguration() with
                                    | Error errors -> failOperation (errors |> String.concat "; ")
                                    | Ok snapshot ->
                                        try
                                            let session = IpcAbi.Session.Create(IpcAbi.targetIdentity selectedTarget, snapshot)
                                            session.SetLoaderState(IpcAbi.LifecycleState.Starting, 0)
                                            ipcSession <- Some session
                                            sessionTarget <- Some selectedTarget
                                            runtimeLabel.Text <- $"waiting | {session.Names.Token[..7]}"
                                            let configBytes = IpcAbi.serializeConfig snapshot
                                            let pid = selectedTarget.ProcessId
                                            Task.Run((fun () -> ManualMap.inject payloadBytes pid configBytes session.MappingHandle), cancellation.Token)
                                                .ContinueWith(fun (injection: Task<Result<nativeint, string>>) ->
                                                    dispatch (fun () ->
                                                        Array.Clear(payloadBytes, 0, payloadBytes.Length)
                                                        if injection.IsCanceled || cancellation.IsCancellationRequested then
                                                            appendActivity "Injection cancelled"
                                                            disposeSession()
                                                            setState LoaderState.Idle
                                                            finishOperation()
                                                        elif injection.IsFaulted then
                                                            appendActivity $"ERROR: {injection.Exception.GetBaseException().Message}"
                                                            disposeSession()
                                                            failOperation (injection.Exception.GetBaseException().Message)
                                                        else
                                                            match injection.Result with
                                                            | Error message ->
                                                                appendActivity $"ERROR: {message}"
                                                                disposeSession()
                                                                failOperation message
                                                            | Ok remoteBase ->
                                                                appendActivity "Injected"
                                                                setState LoaderState.WaitingForReady
                                                                finishOperation()))
                                            |> ignore
                                        with error -> failOperation error.Message))
                    |> ignore

        let discoverAndAutoInject () =
            if state.TryTransition(LoaderState.DiscoveringTarget) then
                stateLabel.Text <- LoaderState.describe LoaderState.DiscoveringTarget
                setBusy true
                let cancellation = new CancellationTokenSource()
                operation <- Some cancellation
                appendActivity "Scanning for target..."
                Task.Run((fun () -> TargetDiscovery.discover()), cancellation.Token)
                    .ContinueWith(fun (completed: Task<TargetDiscovery.Discovery>) ->
                        dispatch (fun () ->
                            if completed.IsCanceled || cancellation.IsCancellationRequested then
                                appendActivity "Scan cancelled"
                                setState LoaderState.Idle
                                finishOperation()
                            elif completed.IsFaulted then
                                failOperation (completed.Exception.GetBaseException().Message)
                            else
                                let discovery = completed.Result
                                let oldTargets = targets
                                targets <- discovery.Targets
                                disposeTargets oldTargets
                                discovery.Issues |> List.iter (fun issue -> appendActivity $"Issue: {issue}")
                                match targets with
                                | [] ->
                                    appendActivity "No target found"
                                    targetDetails.Text <- "No Minecraft window found"
                                    setState LoaderState.Idle
                                    finishOperation()
                                | first :: rest ->
                                    let validTargets = targets |> List.filter (fun t -> TargetDiscovery.revalidate t |> List.isEmpty)
                                    if validTargets.Length > 1 then
                                        let choiceForm = new Form(Text = "Select target", FormBorderStyle = FormBorderStyle.FixedDialog, Width = 500, Height = 200, StartPosition = FormStartPosition.CenterParent, BackColor = Color.FromArgb(39, 39, 42), ForeColor = Color.FromArgb(229, 229, 231))
                                        let lbl = new Label(Text = "Multiple Minecraft windows detected. Select one:", Dock = DockStyle.Top, Height = 35, TextAlign = ContentAlignment.MiddleLeft, Font = new System.Drawing.Font("Segoe UI", 10.f), Padding = System.Windows.Forms.Padding(8))
                                        let box = new ComboBox(DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Top, Font = new System.Drawing.Font("Segoe UI", 10.f))
                                        validTargets |> List.iter (fun t ->
                                            let title = if String.IsNullOrWhiteSpace(t.WindowTitle) then "Minecraft" else t.WindowTitle
                                            box.Items.Add($"PID {t.ProcessId}  |  {title}") |> ignore)
                                        let btnPanel = new Panel(Dock = DockStyle.Bottom, Height = 40)
                                        let okBtn = new Button(Text = "Inject", FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(72, 196, 150), ForeColor = Color.FromArgb(39, 39, 42), Dock = DockStyle.Right, Width = 100)
                                        let cancelBtn = new Button(Text = "Cancel", FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(53, 53, 58), ForeColor = Color.FromArgb(229, 229, 231), Dock = DockStyle.Left, Width = 100)
                                        btnPanel.Controls.Add(cancelBtn)
                                        btnPanel.Controls.Add(okBtn)
                                        box.SelectedIndex <- 0
                                        let selected = ref None
                                        okBtn.Click.Add(fun _ -> selected := Some validTargets[box.SelectedIndex]; choiceForm.Close())
                                        cancelBtn.Click.Add(fun _ -> choiceForm.Close())
                                        choiceForm.Controls.Add(btnPanel)
                                        choiceForm.Controls.Add(box)
                                        choiceForm.Controls.Add(lbl)
                                        choiceForm.ShowDialog(form) |> ignore
                                        choiceForm.Dispose()
                                        if selected.Value.IsSome then
                                            let chosen = selected.Value.Value
                                            let errors = TargetDiscovery.revalidate chosen
                                            if not errors.IsEmpty then
                                                let msg = errors |> String.concat "; "
                                                appendActivity $"Target invalid: {msg}"
                                                targetDetails.Text <- "Target invalid"
                                                setState LoaderState.Idle
                                                finishOperation()
                                            else
                                                let titleText = if String.IsNullOrWhiteSpace(chosen.WindowTitle) then "Minecraft" else chosen.WindowTitle
                                                targetDetails.Text <- $"PID {chosen.ProcessId}  |  {chosen.Architecture}  |  {titleText}"
                                                appendActivity $"Target selected: PID {chosen.ProcessId}"
                                                setState LoaderState.Idle
                                                finishOperation()
                                                startInjection chosen
                                        else
                                            appendActivity "Target selection cancelled"
                                            targetDetails.Text <- "Selection cancelled"
                                            setState LoaderState.Idle
                                            finishOperation()
                                    else
                                        let errors = TargetDiscovery.revalidate first
                                        if not errors.IsEmpty then
                                            let msg = errors |> String.concat "; "
                                            appendActivity $"Target invalid: {msg}"
                                            targetDetails.Text <- "Target invalid"
                                            setState LoaderState.Idle
                                            finishOperation()
                                        else
                                            let titleText = if String.IsNullOrWhiteSpace(first.WindowTitle) then "Minecraft" else first.WindowTitle
                                            targetDetails.Text <- $"PID {first.ProcessId}  |  {first.Architecture}  |  {titleText}"
                                            appendActivity $"Target found: PID {first.ProcessId}"
                                            setState LoaderState.Idle
                                            finishOperation()
                                            startInjection first))
                    |> ignore

        cancelButton.Click.Add(fun _ ->
            operation |> Option.iter (fun value -> value.Cancel())
            appendActivity "Cancellation requested")

        stopButton.Click.Add(fun _ -> requestShutdown false)

        let mutable leftToggleVk = 0
        let mutable rightToggleVk = 0
        let mutable hitFlickToggleVk = 0x14
        let mutable capturingHotkey = 0

        leftHotkeyBtn.Click.Add(fun _ ->
            capturingHotkey <- 1
            leftHotkeyBtn.Text <- "Press a key..."
            (form.Activate() |> ignore))
        rightHotkeyBtn.Click.Add(fun _ ->
            capturingHotkey <- 2
            rightHotkeyBtn.Text <- "Press a key..."
            (form.Activate() |> ignore))
        hitFlickHotkeyBtn.Click.Add(fun _ ->
            capturingHotkey <- 3
            hitFlickHotkeyBtn.Text <- "Press a key..."
            (form.Activate() |> ignore))

        form.KeyPreview <- true
        form.KeyDown.Add(fun e ->
            if capturingHotkey <> 0 then
                e.SuppressKeyPress <- true
                let vk = int e.KeyCode
                if vk = 0x1B then
                    capturingHotkey <- 0
                    leftHotkeyBtn.Text <- vkName leftToggleVk
                    rightHotkeyBtn.Text <- vkName rightToggleVk
                    hitFlickHotkeyBtn.Text <- vkName hitFlickToggleVk
                else
                    if capturingHotkey = 1 then
                        leftToggleVk <- vk
                        leftHotkeyBtn.Text <- vkName vk
                    elif capturingHotkey = 2 then
                        rightToggleVk <- vk
                        rightHotkeyBtn.Text <- vkName vk
                    else
                        hitFlickToggleVk <- vk
                        hitFlickHotkeyBtn.Text <- vkName vk
                    capturingHotkey <- 0)

        let settingControls: Control array = [|
            leftEnabled; leftMinimum; leftMaximum; leftMode; leftHold; leftTrigger
            leftBreak; breakMinimum; breakMaximum; breakWhitelist
            rightEnabled; rightMinimum; rightMaximum; rightMode; rightHold
            rightDelay; rightWhitelistEnabled; rightWhitelist
            hitFlickEnabled
        |]
        settingControls |> Array.iter (fun control ->
            match control with
            | :? CheckBox as box -> box.CheckedChanged.Add(fun _ -> publishConfig())
            | :? NumericUpDown as number -> number.ValueChanged.Add(fun _ -> publishConfig())
            | :? ComboBox as box -> box.SelectedIndexChanged.Add(fun _ -> publishConfig())
            | :? TextBox as box -> box.TextChanged.Add(fun _ -> publishConfig())
            | _ -> ())

        let monitor = new System.Windows.Forms.Timer(Interval = 500)
        monitor.Tick.Add(fun _ ->
            match ipcSession, sessionTarget with
            | Some session, Some target ->
                try
                    session.TouchHeartbeat()
                    let status = session.ReadStatus()
                    let targetErrors = TargetDiscovery.revalidate target
                    runtimeLabel.Text <- $"{status.PayloadState} | gen {status.Generation}/{status.LastAcceptedGeneration}"
                    if not targetErrors.IsEmpty && state.State <> LoaderState.Stopping then
                        let message = targetErrors |> String.concat "; "
                        if message <> lastMonitorMessage then
                            lastMonitorMessage <- message
                            appendActivity $"ERROR: {message}"
                        requestShutdown false
                    elif status.PayloadState = IpcAbi.LifecycleState.Ready && state.State = LoaderState.WaitingForReady then
                        session.SetLoaderState(IpcAbi.LifecycleState.Ready, 0)
                        setState LoaderState.Running
                        stopButton.Enabled <- true
                        lastMonitorMessage <- ""
                    elif status.PayloadState = IpcAbi.LifecycleState.Failed && state.State <> LoaderState.Stopping then
                        let message = $"Payload failed (code {status.ErrorCode})"
                        if message <> lastMonitorMessage then
                            lastMonitorMessage <- message
                            appendActivity $"ERROR: {message}"
                        requestShutdown false
                with error ->
                    if state.State <> LoaderState.Stopping && error.Message <> lastMonitorMessage then
                        lastMonitorMessage <- error.Message
                        appendActivity $"ERROR: {error.Message}"
                        requestShutdown false
            | _ -> ())
        monitor.Start()

        let armed = ref true
        let mutable hotkeyRunning = true
        let leftToggleWasDown = ref false
        let rightToggleWasDown = ref false
        let flickToggleWasDown = ref false
        let comboDown () =
            (ShellNative.GetAsyncKeyState(VK_CONTROL) &&& 0x8000s) <> 0s &&
            (ShellNative.GetAsyncKeyState(VK_SHIFT) &&& 0x8000s) <> 0s &&
            (ShellNative.GetAsyncKeyState(VK_INSERT) &&& 0x8000s) <> 0s
        let hotkeyThread = new Thread(fun () ->
            while hotkeyRunning && not form.IsDisposed do
                try
                    let isDown = comboDown ()
                    if isDown && !armed && not form.IsDisposed && form.IsHandleCreated then
                        armed := false
                        form.BeginInvoke(Action(fun () ->
                            if not form.IsDisposed then
                                if form.Visible then
                                    form.Hide()
                                else
                                    form.Show()
                                    form.BringToFront()
                                    form.Activate())) |> ignore
                    if not isDown then
                        armed := true
                    if capturingHotkey = 0 then
                        if leftToggleVk <> 0 then
                            let lDown = (ShellNative.GetAsyncKeyState(leftToggleVk) &&& 0x8000s) <> 0s
                            if lDown && not !leftToggleWasDown && not form.IsDisposed && form.IsHandleCreated then
                                form.BeginInvoke(Action(fun () ->
                                    if not form.IsDisposed then
                                        leftEnabled.Checked <- not leftEnabled.Checked)) |> ignore
                            leftToggleWasDown := lDown
                        if rightToggleVk <> 0 then
                            let rDown = (ShellNative.GetAsyncKeyState(rightToggleVk) &&& 0x8000s) <> 0s
                            if rDown && not !rightToggleWasDown && not form.IsDisposed && form.IsHandleCreated then
                                form.BeginInvoke(Action(fun () ->
                                    if not form.IsDisposed then
                                        rightEnabled.Checked <- not rightEnabled.Checked)) |> ignore
                            rightToggleWasDown := rDown
                        if hitFlickToggleVk <> 0 then
                            let fDown = (ShellNative.GetAsyncKeyState(hitFlickToggleVk) &&& 0x8000s) <> 0s
                            if fDown && not !flickToggleWasDown && not form.IsDisposed && form.IsHandleCreated then
                                form.BeginInvoke(Action(fun () ->
                                    if not form.IsDisposed then
                                        hitFlickEnabled.Checked <- not hitFlickEnabled.Checked)) |> ignore
                            flickToggleWasDown := fDown
                with _ -> ()
                Thread.Sleep(25))
        hotkeyThread.IsBackground <- true
        hotkeyThread.Name <- "WinHelper hotkey poller"
        hotkeyThread.Start()

        form.FormClosing.Add(fun args ->
            if ipcSession.IsSome && not closeAfterShutdown then
                args.Cancel <- true
                requestShutdown true
            else
                operation |> Option.iter (fun value -> value.Cancel())
                monitor.Stop()
                monitor.Dispose()
                hotkeyRunning <- false
                let zeroString (s: string) =
                    if not (isNull s) && s.Length > 0 then
                        try
                            let gch = Runtime.InteropServices.GCHandle.Alloc(s, Runtime.InteropServices.GCHandleType.Pinned)
                            try
                                let ptr = gch.AddrOfPinnedObject()
                                let charDataPtr = IntPtr.Add(ptr, 12)
                                for i in 0 .. s.Length - 1 do
                                    Marshal.WriteInt16(charDataPtr, i * 2, 0s)
                            finally
                                gch.Free()
                        with _ -> ()
                let rec zeroControlText (c: Control) =
                    zeroString c.Text
                    c.Text <- null
                    for child in c.Controls do
                        zeroControlText child
                zeroControlText form
                zeroString "SYSTEM HELPER"
                zeroString "Loader control plane"
                zeroString "Stop"
                zeroString "Cancel"
                zeroString "Left clicker"
                zeroString "Right clicker"
                zeroString "Idle"
                zeroString "offline"
                GC.Collect(2, GCCollectionMode.Forced, true)
                GC.WaitForPendingFinalizers()
                GC.Collect(2, GCCollectionMode.Forced, true)
                disposeSession()
                disposeTargets targets
                targets <- [])

        form.Shown.Add(fun _ ->
            form.BringToFront()
            form.Activate()
            discoverAndAutoInject())

        if smokeTest then
            form.CreateControl() |> ignore
            form.Dispose()
        else
            Application.Run(form)

    let private runOnSta smokeTest =
        let mutable error: exn option = None
        let thread = new Thread(ThreadStart(fun () ->
            try
                Application.SetHighDpiMode(HighDpiMode.SystemAware) |> ignore
                Application.EnableVisualStyles()
                Application.SetCompatibleTextRenderingDefault(false)
                runWindow smokeTest
            with caught -> error <- Some caught))
        thread.Name <- "WinHelper WinForms UI"
        thread.SetApartmentState(ApartmentState.STA)
        thread.Start()
        thread.Join()
        match error with
        | Some caught -> raise caught
        | None -> 0

    let run () = runOnSta false
    let smokeTest () = runOnSta true

let private printUsage () =
    printfn "System Helper managed loader"
    printfn "Usage:"
    printfn "  dotnet fsi loader.fsx                                Validate default configuration"
    printfn "  dotnet fsi loader.fsx --inspect <payload.dll>         Inspect a local PE payload"
    printfn "  dotnet fsi loader.fsx --discover"
    printfn "      List matching Minecraft windows and validate their process identity"
    printfn "  dotnet fsi loader.fsx --ui"
    printfn "      Start the STA WinForms loader shell"
    printfn "  dotnet fsi loader.fsx --ipc-self-test"
    printfn "      Validate the versioned IPC ABI and secured per-run kernel objects"
    printfn "  dotnet fsi loader.fsx --abi-check"
    printfn "      Verify F# IpcAbi constants match jvm_helper.h"
    printfn "  dotnet fsi loader.fsx --gen-keys <priv.pem> <pub.pem>"
    printfn "      Generate an RSA signing key pair"
    printfn "  dotnet fsi loader.fsx --sign <payload.dll> <priv.pem> <metadata.out>"
    printfn "      Sign payload and write release metadata"
    printfn "  dotnet fsi loader.fsx --verify <payload.dll> <metadata> <pub.pem>"
    printfn "      Verify payload against signed metadata"
    printfn "  dotnet fsi loader.fsx --acquire <base-url> <pub.pem>"
    printfn "      Download, verify, and inspect payload"
    printfn "  dotnet fsi loader.fsx --local-inject <payload.dll>"
    printfn "      Load local DLL, discover target, create IPC, inject, and monitor"

let private run arguments =
    match arguments with
    | [||] ->
        let errors = Configuration.validate Configuration.defaults
        if errors.IsEmpty then
            printfn "State: %s" (LoaderState.describe LoaderState.Idle)
            printfn "Default configuration: valid (ABI %u)" Configuration.Version
            printUsage ()
            0
        else
            errors |> List.iter (eprintfn "Configuration error: %s")
            1
    | [| "--inspect"; path |] ->
        try
            let image = File.ReadAllBytes(path) |> Pe.inspect
            printfn "Valid AMD64 PE32+ image"
            printfn "Image base: 0x%016X" image.ImageBase
            printfn "Image size: %u bytes" image.SizeOfImage
            printfn "Entry point RVA: 0x%08X" image.EntryPointRva
            printfn "Sections: %d" image.Sections.Length
            for section in image.Sections do
                printfn "  %-8s RVA=0x%08X virtual=%u raw=%u" section.Name section.VirtualAddress section.VirtualSize section.RawSize
            0
        with
        | :? IOException as error ->
            eprintfn "Payload read failed: %s" error.Message
            1
        | :? UnauthorizedAccessException as error ->
            eprintfn "Payload read failed: %s" error.Message
            1
        | :? InvalidDataException as error ->
            eprintfn "Payload validation failed: %s" error.Message
            1
    | [| "--discover" |] ->
        let discovery = TargetDiscovery.discover()
        try
            if discovery.Targets.IsEmpty then
                printfn "No matching LWJGL, LWJGL3, or GLFW30 windows found"
            else
                printfn "Found %d candidate(s)" discovery.Targets.Length
                for index, target in discovery.Targets |> List.indexed do
                    let errors = TargetDiscovery.revalidate target
                    printfn "[%d] HWND=0x%X PID=%u class=%s" index (uint64 target.WindowHandle) target.ProcessId target.WindowClass
                    printfn "    Title:        %s" (if String.IsNullOrEmpty(target.WindowTitle) then "<empty>" else target.WindowTitle)
                    printfn "    Executable:   %s" target.ExecutablePath
                    printfn "    Architecture: %A" target.Architecture
                    printfn "    Created:      %O" target.CreationTimeUtc
                    printfn "    Liveness:     %s" (if errors.IsEmpty then "valid" else "invalid")
                    errors |> List.iter (printfn "    Error:        %s")
            discovery.Issues |> List.iter (eprintfn "Discovery issue: %s")
            if discovery.Issues.IsEmpty then 0 else 1
        finally
            discovery.Targets |> List.iter (fun target -> (target :> IDisposable).Dispose())
    | [| "--ui" |] ->
        try WinFormsShell.run()
        with error ->
            eprintfn "UI startup failed: %s" error.Message
            1
    | [| "--ui-smoke-test" |] ->
        try WinFormsShell.smokeTest()
        with error ->
            eprintfn "UI smoke test failed: %s" error.Message
            1
    | [| "--ipc-self-test" |] ->
        try
            match IpcAbi.selfTest() with
            | Ok(names, generation) ->
                printfn "IPC self-test succeeded"
                printfn "  ABI:                 %u" IpcAbi.Version
                printfn "  Mapping size:        %d bytes" IpcAbi.MappingSize
                printfn "  Configuration size:  %d bytes" IpcAbi.ConfigSize
                printfn "  Stable generation:   %d" generation
                printfn "  Token:                %s" names.Token
                0
            | Error message ->
                eprintfn "IPC self-test failed: %s" message
                1
        with error ->
            eprintfn "IPC self-test failed: %s" error.Message
            1
    | [| "--abi-check" |] ->
        let errors = IpcAbi.verifyCHeader()
        if errors.IsEmpty then
            printfn "ABI check passed — F# IpcAbi matches jvm_helper.h"
            printfn "  Magic:           0x%08X" IpcAbi.Magic
            printfn "  ABI version:      %u" IpcAbi.Version
            printfn "  Mapping size:     %d" IpcAbi.MappingSize
            printfn "  Header size:      %d" IpcAbi.HeaderSize
            printfn "  Config offset:    %d" IpcAbi.ConfigOffset
            printfn "  Config size:      %d" IpcAbi.ConfigSize
            printfn "  Config version:   %u" Configuration.Version
            0
        else
            errors |> List.iter (eprintfn "ABI mismatch: %s")
            1
    | [| "--gen-keys"; privPath; pubPath |] ->
        try
            let priv, pub = SignatureVerification.generateKeyPair()
            File.WriteAllText(privPath, priv)
            File.WriteAllText(pubPath, pub)
            printfn "Generated RSA key pair"
            printfn "  Private key: %s" privPath
            printfn "  Public key:  %s" pubPath
            0
        with
        | :? IOException as error ->
            eprintfn "Key write failed: %s" error.Message
            1
        | :? CryptographicException as error ->
            eprintfn "Key generation failed: %s" error.Message
            1
    | [| "--sign"; payloadPath; privPath; metadataPath |] ->
        try
            let payloadBytes = File.ReadAllBytes(payloadPath)
            let privPem = File.ReadAllText(privPath)
            use privateKey = SignatureVerification.loadPrivateKey(privPem)
            let digest = SignatureVerification.computeSha256(payloadBytes)
            let signature = SignatureVerification.signPayload payloadBytes privateKey
            let keyId = SignatureVerification.computeKeyId privateKey
            let expiration = uint64 (DateTimeOffset.UtcNow.ToUnixTimeSeconds()) + 365UL * 24UL * 3600UL
            let metadata = {
                ReleaseMetadata.FormatVersion = ReleaseMetadata.FormatVersion
                ReleaseMetadata.LoaderVersion = Loader.Version
                ReleaseMetadata.PayloadVersion = Loader.PayloadVersion
                ReleaseMetadata.AbiVersion = Configuration.Version
                ReleaseMetadata.Architecture = ReleaseMetadata.Architecture.Amd64
                ReleaseMetadata.PayloadLength = uint64 payloadBytes.Length
                ReleaseMetadata.Sha256 = digest
                ReleaseMetadata.Signature = signature
                ReleaseMetadata.SigningKeyId = keyId
                ReleaseMetadata.ExpirationUnixSeconds = expiration
            }
            let metadataBytes = ReleaseMetadata.serialize metadata
            File.WriteAllBytes(metadataPath, metadataBytes)
            printfn "Signed payload"
            printfn "  Payload:  %s (%d bytes)" payloadPath payloadBytes.Length
            printfn "  Metadata: %s (%d bytes)" metadataPath metadataBytes.Length
            printfn "  SHA-256:  %s" (Convert.ToHexString(digest).ToLowerInvariant())
            printfn "  Key ID:   %s" (Convert.ToHexString(keyId).ToLowerInvariant())
            0
        with
        | :? IOException as error ->
            eprintfn "File error: %s" error.Message
            1
        | :? InvalidDataException as error ->
            eprintfn "Signing failed: %s" error.Message
            1
        | :? CryptographicException as error ->
            eprintfn "Cryptographic error: %s" error.Message
            1
    | [| "--verify"; payloadPath; metadataPath; pubPath |] ->
        try
            let payloadBytes = File.ReadAllBytes(payloadPath)
            let metadataBytes = File.ReadAllBytes(metadataPath)
            let pubPem = File.ReadAllText(pubPath)
            use publicKey = SignatureVerification.loadPublicKey(pubPem)
            let constraints = defaultConstraints()
            match verifyRelease metadataBytes payloadBytes publicKey constraints with
            | Ok(metadata, image) ->
                printRelease metadata image
                0
            | Error message ->
                eprintfn "Verification failed: %s" message
                1
        with
        | :? IOException as error ->
            eprintfn "File error: %s" error.Message
            1
        | :? CryptographicException as error ->
            eprintfn "Cryptographic error: %s" error.Message
            1
    | [| "--acquire"; baseUrl; pubPath |] ->
        try
            let pubPem = File.ReadAllText(pubPath)
            use publicKey = SignatureVerification.loadPublicKey(pubPem)
            let config = Acquisition.defaultConfig baseUrl
            use cts = new CancellationTokenSource(TimeSpan.FromSeconds(float config.TimeoutSeconds))
            match Acquisition.download config cts.Token with
            | Ok(metadataBytes, payloadBytes) ->
                printfn "Downloaded %d metadata bytes, %d payload bytes" metadataBytes.Length payloadBytes.Length
                let constraints = defaultConstraints()
                match verifyRelease metadataBytes payloadBytes publicKey constraints with
                | Ok(metadata, image) ->
                    printRelease metadata image
                    0
                | Error message ->
                    eprintfn "Verification failed: %s" message
                    1
            | Error message ->
                eprintfn "Acquisition failed: %s" message
                1
        with
        | :? IOException as error ->
            eprintfn "File error: %s" error.Message
            1
        | :? CryptographicException as error ->
            eprintfn "Cryptographic error: %s" error.Message
            1
    | [| "--local-inject"; dllPath |] ->
        try
            printfn "WinHelper local injection test"
            printfn ""
            printfn "Reading payload: %s" dllPath
            let payloadBytes = File.ReadAllBytes(dllPath)
            printfn "  Payload size: %d bytes" payloadBytes.Length

            printfn "Validating PE..."
            let image = Pe.inspect payloadBytes
            printfn "  Valid AMD64 PE32+ image, %d sections, entry RVA 0x%08X" image.Sections.Length image.EntryPointRva

            printfn "Discovering targets..."
            let discovery = TargetDiscovery.discover()
            discovery.Issues |> List.iter (fun issue -> eprintfn "  Discovery issue: %s" issue)
            if discovery.Targets.IsEmpty then
                eprintfn "No matching Minecraft windows found."
                eprintfn "Start Lunar Client 1.8.9, join a world, then run this."
                1
            else
                printfn "Found %d candidate(s)" discovery.Targets.Length
                let validTargets =
                    discovery.Targets
                    |> List.filter (fun target -> TargetDiscovery.revalidate target |> List.isEmpty)
                if validTargets.IsEmpty then
                    eprintfn "No valid targets (wrong architecture, not javaw, or process issues)."
                    discovery.Targets |> List.iter (fun target -> (target :> IDisposable).Dispose())
                    1
                else
                    let target = validTargets.Head
                    printfn "Selected: HWND=0x%X PID=%u %s" (uint64 target.WindowHandle) target.ProcessId target.WindowClass
                    printfn "  Executable: %s" target.ExecutablePath
                    printfn "  Architecture: %A" target.Architecture

                    let config = Configuration.defaults
                    let configBytes = IpcAbi.serializeConfig config
                    printfn "Serializing config (%d bytes, version %u)" configBytes.Length config.Version

                    printfn "Creating per-run IPC (anonymous)..."
                    use session = IpcAbi.Session.Create(IpcAbi.targetIdentity target, config)
                    session.SetLoaderState(IpcAbi.LifecycleState.Starting, 0)
                    printfn "  Token: %s" session.Names.Token

                    printfn "Injecting payload into PID %u..." target.ProcessId
                    match ManualMap.inject payloadBytes target.ProcessId configBytes session.MappingHandle with
                    | Error message ->
                        eprintfn "Injection failed: %s" message
                        (target :> IDisposable).Dispose()
                        1
                    | Ok remoteBase ->
                        printfn "Injected at remote base 0x%X" (uint64 (int64 remoteBase))
                        printfn ""
                        printfn "Monitoring payload lifecycle (press Ctrl+C to stop)..."
                        printfn ""
                        let mutable running = true
                        let mutable lastState = IpcAbi.LifecycleState.None
                        use cts = new CancellationTokenSource()
                        System.Console.CancelKeyPress.Add(fun args ->
                            args.Cancel <- true
                            running <- false
                            cts.Cancel())
                        let monitorThread = Thread(ThreadStart(fun () ->
                            while running do
                                Thread.Sleep(250)
                                try
                                    session.TouchHeartbeat()
                                    let status = session.ReadStatus()
                                    if status.PayloadState <> lastState then
                                        lastState <- status.PayloadState
                                        let time = DateTimeOffset.Now.ToString("HH:mm:ss")
                                        printfn "[%s] Payload state: %A (error=%d, gen=%d/%d)"
                                            time status.PayloadState status.ErrorCode
                                            status.Generation status.LastAcceptedGeneration
                                    let targetErrors = TargetDiscovery.revalidate target
                                    if not targetErrors.IsEmpty && running then
                                        printfn "Target lost: %s" (targetErrors |> String.concat "; ")
                                        running <- false
                                    if status.PayloadState = IpcAbi.LifecycleState.Stopped
                                       || status.PayloadState = IpcAbi.LifecycleState.Failed then
                                        running <- false
                                with _ -> ()))
                        monitorThread.IsBackground <- true
                        monitorThread.Start()
                        monitorThread.Join()

                        printfn ""
                        printfn "Requesting stop..."
                        try
                            session.RequestStop()
                            if session.WaitForStopAcknowledgement(TimeSpan.FromSeconds(3.0)) then
                                printfn "Stop acknowledged."
                            else
                                printfn "Stop acknowledgement timed out."
                        with error -> printfn "Stop error: %s" error.Message

                        (target :> IDisposable).Dispose()
                        printfn "Done."
                        0
        with
        | :? IOException as error ->
            eprintfn "File error: %s" error.Message
            1
        | :? InvalidDataException as error ->
            eprintfn "Validation failed: %s" error.Message
            1
        | error ->
            eprintfn "Error: %s" error.Message
            1
    | _ ->
        printUsage ()
        2

let private appArgs =
    let envArgs = System.Environment.GetEnvironmentVariable("APPHELPER_ARGS")
    if not (System.String.IsNullOrEmpty(envArgs)) then
        envArgs.Split([|' '|], System.StringSplitOptions.RemoveEmptyEntries)
    else
        fsi.CommandLineArgs |> Array.skip 1

appArgs
|> run
|> Environment.Exit
