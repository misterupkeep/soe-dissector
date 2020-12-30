soe_protocol= Proto("SOE",  "Sony Online Entertainment's Reliable UDP Protocol")

soe_opcodes = {
    [0x0001]="SOE_SESSION_REQUEST",
    [0x0002]="SOE_SESSION_REPLY",

    [0x0003]="SOE_MULTI_SOE", -- Multiple packets, grouped together
    [0x0004]="SOE_NOT_USED", -- Seems to be a reserved opcode

    [0x0005]="SOE_DISCONNECT",
    [0x0006]="SOE_PING",

    [0x0007]="SOE_NET_STATUS_REQ", -- Client Network Status Update
    [0x0008]="SOE_NET_STATUS_RES", -- Server Network Status Update

    -- The SOE Reliable UDP protocol has in place several channels
    -- for transmitting data, however no game actually seems to use
    -- any channel other than A.
    [0x0009]="SOE_CHL_DATA_A", -- Data Packet
    [0x000A]="SOE_CHL_DATA_B",
    [0x000B]="SOE_CHL_DATA_C",
    [0x000C]="SOE_CHL_DATA_D",

    [0x000D]="SOE_DATA_FRAG_A", -- Fragmented Data Packet
    [0x000E]="SOE_DATA_FRAG_B",
    [0x000F]="SOE_DATA_FRAG_C",
    [0x0010]="SOE_DATA_FRAG_D",

    [0x0011]="SOE_OUT_ORDER_PKT_A", -- Out of Order Packet
    [0x0012]="SOE_OUT_ORDER_PKT_B",
    [0x0013]="SOE_OUT_ORDER_PKT_C",
    [0x0014]="SOE_OUT_ORDER_PKT_D",

    [0x0015]="SOE_ACK_A", -- Acknowledge Packet
    [0x0016]="SOE_ACK_B",
    [0x0017]="SOE_ACK_C",
    [0x0018]="SOE_ACK_D",

    [0x0019]="SOE_MULTI_A", -- Multi Packet
    [0x001A]="SOE_MULTI_B",
    [0x001B]="SOE_MULTI_C",
    [0x001C]="SOE_MULTI_D",

    [0x001D]="SOE_FATAL_ERR",
    [0x001E]="SOE_FATAL_ERR_REPLY",
}

packet_type = ProtoField.uint16(
    "soe.packet_type",
    "packetType",
    base.HEX,
    soe_opcodes
)

-------------------------
-- SOE_SESSION_REQUEST --
-------------------------
crc_length = ProtoField.uint32("soe.crc_length", "crcLength", base.DEC)
connection_id = ProtoField.uint32("soe.connection_id", "connectionId", base.HEX)
client_udp_size = ProtoField.uint32("soe.client_udp_size", "clientUdpSize", base.DEC)
-- This seems to be a constant footer in client reqs in the packet logs I have
-- Probably protocol version. Panic if it isn't CGAPI_527 (since this dissector probably breaks).
cgapi_527_string = ProtoField.stringz("soe.cgapi_527_string" ,"cgApi527String", base.ASCII)

--------------------------
--   SOE_SESSION_REPLY  --
--------------------------
-- connection_id goes here
crc_seed = ProtoField.uint32("soe.crc_seed", "crcSeed", base.HEX)
-- The same length as in SOE_SESSION_REQUEST, just 3 bytes shorter lol
-- The implication of this is that the crc_length in sess.reqs will never exceed 255
crc_length_byte = ProtoField.uint8("soe.crc_length", "crcLength", base.DEC)
use_compression = ProtoField.bool("soe.use_compression", "useCompression")
use_encryption = ProtoField.bool("soe.use_encryption", "useEncryption")
server_udp_size = ProtoField.uint32("soe.server_udp_size", "serverUdpSize", base.DEC)
-- Seems to be a constant '3'
stray_uint32 = ProtoField.uint32("soe.stray_uint32", "strayUInt32", base.DEC)

--------------------
-- SOE_CHL_DATA_A --
--------------------
deflated_data = ProtoField.bytes("soe.deflated_data", "deflatedData")
sequence_number = ProtoField.uint16("soe.sequence_number", "sequenceNumber", base.DEC)
game_data = ProtoField.bytes("soe.game_data", "gameData")

---------------------
-- SOE_DATA_FRAG_A --
---------------------
fragmented_game_data = ProtoField.bytes("soe.fragmented_game_data", "fragmentedGameData")

-------------------------
-- SOE_OUT_ORDER_PKT_A --
-------------------------
-- sequence_number goes here

---------------
-- SOE_ACK_A --
---------------
-- use_compression goes here
-- sequence_number goes here
crc_footer = ProtoField.bytes("soe.crc_footer", "crcFooter")

-------------------
-- SOE_MULTI_SOE --
-------------------
payload_size = ProtoField.uint8("soe.payload_size", "payloadLength", base.HEX)

soe_protocol.fields = {
    packet_type, -- Header
    crc_length, connection_id, client_udp_size, cgapi_527_string, -- Session Request
    crc_seed, crc_length_byte, use_compression, use_encryption, server_udp_size, stray_uint32, -- Session Reply
    sequence_number, game_data, deflated_data, -- Channel Data
    fragmented_game_data, -- Fragmented Packets
    crc_footer, -- Acknowledge Packets
    payload_size, -- Grouped Packets
}

string.starts_with = function(self, prefix)
    return self:find("^" .. prefix) ~= nil
end

-- Try decompressing
function inflate(input)
    local byte_array = input:bytes(3) -- Skip opcode and zflag
    byte_array:set_size(byte_array:len() - 2) -- Skip CRC footer; NOTE: ocassionally 3
    return zlib.inflate()(byte_array:raw()) -- Convert ByteArray to String and inflate
end

function soe_session_request(buffer, subtree)
    subtree:add(crc_length,       buffer(2,4))
    subtree:add(connection_id,    buffer(6,4))
    subtree:add(client_udp_size,  buffer(10,4))
    subtree:add(cgapi_527_string, buffer(14))
end

function soe_session_reply(buffer, subtree)
    subtree:add(connection_id,   buffer(2,4))
    subtree:add(crc_seed,        buffer(6,4))
    subtree:add(crc_length_byte, buffer(10,1))
    subtree:add(use_compression, buffer(11,1))
    subtree:add(use_encryption,  buffer(12,1))
    subtree:add(server_udp_size, buffer(13,4))
    subtree:add(stray_uint32,    buffer(17,4)):append_text(" (Should be 3, footer)")
end

-- Regular *and* fragmented data packets
-- opcode is for nice field names
-- _recursive disables zflag, CRC footer parsing (for use inside grouped packets, see: parse_packet())
function soe_data_packet(buffer, subtree, opcode, _recursive)
    if type(_recursive) ~= "boolean" then _recursive = false end

    -- Sets up correct string for tab/tree name
    local data_type_string = (opcode:starts_with("SOE_C") and "Game")
	or (opcode:starts_with("SOE_M") and "Multi-Packet")
	or "Fragmented"
    local tab_name = "Inflated "..data_type_string.." Data"

    -- Is data compressed
    local uses_compression = (not _recursive) and buffer(2,1):uint() ~= 0
    if not _recursive then
	subtree:add(use_compression, buffer(2,1))
    end

    -- Merges the field destination of compression branches
    local final_data -- uses_compression ? inflated_bytes : (buffer + 3)
    local final_tree -- uses_compression ? inflated_data_subtree : subtree
    if uses_compression then
	final_data = ByteArray.new(inflate(buffer), true):tvb(tab_name)
	final_tree = subtree:add(final_data(), tab_name)
    else
	final_tree = subtree
	local offset = 3 - ((_recursive and 1) or 0)
	final_data = buffer(offset, buffer:len() - offset - 2):tvb() -- Cut out the opcode/zflag, crcfooter
    end

    -- SOE_MULTI_SOE packets don't have a sequence_number
    if data_type_string ~= "Multi-Packet" then
	final_tree:add(sequence_number, final_data(0,2))
    end

    -- In non-multi packets, the first two bytes are sequence_number
    -- In multi packets, the first two bytes aren't specially parsed in this tree
    final_tree:add(game_data, final_data(_recursive and 0 or 2))

    if not _recursive then
	subtree:add(crc_footer, buffer(buffer:len() - 2)):append_text(" (Byte longer if client-sent)")
    end

    return final_tree, final_data
end

-- Parameter `_recursive` is used to disable zflag and CRC footer parsing
-- ACK and OUT_ORDER_PKT have the same layout
function soe_ack_outoforder(buffer, subtree, _recursive)
    local i = 2

    if not _recursive then
	subtree:add(use_compression, buffer(i,1))
	i = i + 1
    end

    subtree:add(sequence_number, buffer(i,2))
    i = i + 2

    if not _recursive then
	subtree:add(crc_footer, buffer(i))
    end
end

-- Parameter `_recursive` is used to disable zflag and CRC footer parsing
-- It is set to false when called recursively, and is passed on to soe_data_packet()
-- This happens only inside grouped packets, i.e. SOE_MULTI_SOE
function parse_packet(buffer, subtree, _recursive)
    if type(_recursive) ~= "boolean" then _recursive = false end
    if _recursive then
	subtree:add(packet_type, buffer(0,2))
    end

    local opcode = soe_opcodes[buffer(0,2):uint()]

    if opcode == "SOE_SESSION_REQUEST" then
	soe_session_request(buffer, subtree)
    elseif opcode == "SOE_SESSION_REPLY" then
	soe_session_reply(buffer, subtree)
    elseif opcode:starts_with("SOE_CHL_DATA") or opcode:starts_with("SOE_DATA_FRAG") then
	soe_data_packet(buffer, subtree, opcode, _recursive)
    elseif opcode == "SOE_MULTI_SOE" then
	local final_tree, final_data = soe_data_packet(buffer, subtree, opcode, _recursive)
	function parse_multi_packet(i, no)
	    local packet_size = final_data(i, 1):uint()
	    -- Grouped payload
	    local new_tvb = final_data(i + 1, packet_size):tvb()
	    local new_tree = final_tree:add(new_tvb(), "Grouped SOE Packet #"..no)

	    new_tree:add(payload_size, final_data(i, 1))

	    -- _recursive = t -> skip zflag/crc
	    parse_packet(new_tvb, new_tree, true)

	    if final_data:len() > i + packet_size + 1 then
		parse_multi_packet(i + packet_size + 1, no + 1)
	    end
	end

	parse_multi_packet(0, 1)
    elseif opcode:starts_with("SOE_ACK")
	or opcode:starts_with("SOE_OUT_ORDER_PKT") then
	soe_ack_outoforder(buffer, subtree, _recursive)
    end
end

function soe_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = soe_protocol.name

    local subtree = tree:add(soe_protocol, buffer(), "SOE Reliable UDP Protocol")
    subtree:add(packet_type, buffer(0,2))

    parse_packet(buffer, subtree)
end

function heuristic_checker(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 5 then return false end -- Smallest valid packet size

    local potential_opcode = buffer(0,2):uint() -- Filter by opcodes
    if not (potential_opcode < 0x1E) then return false end

    soe_protocol.dissector(buffer, pinfo, tree)
    return true
end

-- local udp_port = DissectorTable.get("udp.port")
-- udp_port:add(20232, soe_protocol)

soe_protocol:register_heuristic("udp", heuristic_checker)
