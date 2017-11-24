do
	local handover_proto = Proto("ho", "Handover Protocol")

	local F_payload = ProtoField.bytes("ho.payload", "Encoded TLV")
	local F_cmd = ProtoField.string("ho.cmd", "Command")
	local F_id = ProtoField.uint16("ho.id", "Handover Id")
	local F_tlvs_length = ProtoField.uint32("ho.tlvs_length", "TLVs Length")
	local F_tlv = ProtoField.bytes("ho.tlv", "TLV")
	local F_tlv_type = ProtoField.uint16("ho.tlv_type", "Type")
	local F_tlv_length = ProtoField.uint16("ho.tlv_length", "Length")
	local F_tlv_val = ProtoField.string("ho.tlv_val", "Value")

	handover_proto.fields = {
		F_payload, 
		F_cmd, 
		F_id, 
		F_tlvs_length, 
		F_tlv,
		F_tlv_type, 
		F_tlv_length,
		F_tlv_val
	}

	frame_dissector = Dissector.get("eth_withoutfcs")

	cmd_to_text = {
		[1]="Start Handover Src Inst",
		[2]="Start Handover Dst Inst",
		[3]="Start Handover Ack",
		[4]="Buffer Follow Up",
		[5]="Releasing Finished",
		[6]="Releasing Finished Ack",
		[7]="Handover Finished",
		[8]="Handover Finished Ack",
		[256]="Transport Packet"
	}

	function parse_int(buf, len)
		return tostring(buf(0, len):uint())
	end

	function parse_ip(buf, len)
		return tostring(buf(0, len):ipv4())
	end

	function parse_mac(buf, len)
		return tostring(buf(0, len):ether())
	end


	tlv_types = {
		[0] = {"Padding", nil},
		[1] = {"From VNF", parse_int},
		[2] = {"To VNF", parse_int},
		[3] = {"Ether Type", parse_int},
		[4] = {"Ether Source", parse_mac},
		[5] = {"Ether Destination", parse_mac},
		[6] = {"IPv4 Source", parse_ip},
		[7] = {"IPv4 Destination", parse_ip},
		[256] = {"Wrapped Packet", nil}
	}

	local dst = Field.new("eth.dst")

	function handover_proto.dissector(buffer, packet_info, tree)
		if buffer then
			offset = 0
			local subtreeitem = tree:add(handover_proto, buffer(offset))

			v_cmd = buffer(0,2):uint()
			if cmd_to_text[v_cmd] ~= nil then
				cmd_text = cmd_to_text[v_cmd]
			else
				cmd_text = "Unknown"
			end

			subtreeitem:add(F_cmd, buffer(0, 2), string.format("0x%X", v_cmd)):append_text(" (" .. cmd_text .. ")")
			subtreeitem:add(F_id, buffer(2, 2), buffer(2,2):uint())


			offset = offset + 8
			buflen = buffer:len()

			local tlvstreeitem = nil
			if offset < buflen then
				tlvstreeitem = subtreeitem:add(F_payload, buffer(offset))
			end

			while offset <  buflen do
				tlv_type = buffer(offset, 2):uint()
				tlv_length = buffer(offset + 2, 2):uint()

				if tlv_types[tlv_type] ~= nil then
					type_string = tostring(tlv_types[tlv_type][1])
				else
					type_string = tostring(type) .. " (Unknown type)"
				end


				if tlv_types[tlv_type] ~= nil then
					if tlv_type == 256 then
						value_string = "Wrapped Packet"
					elseif tlv_type == 0 then
						value_string = "Padding"
						tlv_length = buflen - offset - 4 
					else
						value_string = tlv_types[tlv_type][2](buffer(offset + 4, tlv_length), tlv_length)
					end
				else
					value_string = "Unknown"
				end

				tlv = tlvstreeitem:add(F_tlv, buffer(offset, tlv_length + 4)):set_text(type_string .. " (" .. value_string .. ")")

				tlv:add(F_tlv_type, buffer(offset, 2), tlv_type)
				tlv:add(F_tlv_length, buffer(offset + 2, 2), tlv_length)				
				offset = offset + 4

				value_tree = tlv:add(F_tlv_val, buffer(offset, tlv_length), value_string)

				if tlv_type == 256 then
					frame_dissector:call(buffer(offset, tlv_length):tvb(), packet_info, value_tree)
				end

				offset = offset + tlv_length
			end

			packet_info.cols.protocol = "Handover"
			packet_info.cols.info = cmd_text .. " to " .. tostring(dst())
		end
	end



	local eth_table = DissectorTable.get("ethertype")
	eth_table:add(0x821c, handover_proto)
end
