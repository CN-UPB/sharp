-- trivial protocol example
-- declare our protocol
do 

	local  test_proto = Proto("testpkt","Handover Test Packet Protocol")

	local F_test_id = ProtoField.uint32("testpkt.id", "Test Id")
	local F_seq_num = ProtoField.uint32("testpkt.seq", "Sequence Number")
	local F_vnf_id = ProtoField.uint16("testpkt.vnf_id", "VNF Id")
	local F_ingr_buf_id = ProtoField.uint8("testpkt.ingress_queue_id", "Ingress Queue Id")
	local F_ingr_buf_len = ProtoField.uint16("testpkt.ingress_queue_len", "Ingress Queue Length")
	local F_egr_buf_id = ProtoField.uint8("testpkt.egress_queue_id", "Egress Queue Id")
	local F_egr_buf_len = ProtoField.uint16("testpkt.egress_queue_len", "Egress Queue Length")
	local F_pkt_len = ProtoField.uint16("testpkt.pkt_len", "Packet Length")
	local F_padding = ProtoField.bytes("testpkt.padding", "Padding")

	test_proto.fields = {F_test_id, F_seq_num, F_vnf_id, F_ingr_buf_id, F_ingr_buf_len, F_egr_buf_id, F_egr_buf_len, F_pkt_len, F_padding}

	-- create a function to dissect it
	function test_proto.dissector(buffer, pinfo, tree)
	    pinfo.cols.protocol = "TEST PACKET"
        pinfo.cols.info = ""

        buf_len = buffer:len()
        offset = 0

        while offset < buf_len do
        	local subtree = tree:add(test_proto,buffer(),"Handover Test Packet")
		    subtree:add(F_test_id, buffer(offset + 0, 4))
		    subtree:add(F_seq_num, buffer(offset + 4, 4))
		    subtree:add(F_vnf_id, buffer(offset + 8, 2))
		    subtree:add(F_ingr_buf_id, buffer(offset + 10, 1))
		    subtree:add(F_ingr_buf_len, buffer(offset + 11, 2))
		    subtree:add(F_egr_buf_id, buffer(offset + 13, 1))
		    subtree:add(F_egr_buf_len, buffer(offset + 14, 2))
		    subtree:add(F_pkt_len, buffer(offset + 16, 2))

		    if tostring(pinfo.cols.info):len() > 0 then
		    	pinfo.cols.info:append(", ")
		    end

		    pinfo.cols.info:append("SEQ=" .. tostring(buffer(offset + 4, 4):uint()) .. " VNF=" .. tostring(buffer(offset + 8, 2):uint()))

		    pkt_len = buffer(offset + 16, 2):uint()

		    if pkt_len > 18 then
		    	subtree:add(F_padding, buffer(offset + 18, pkt_len - 18))
		    end

		    offset = offset + pkt_len
		    break
		end
	end

	-- load the udp.port table
	local udp_table = DissectorTable.get("udp.port")
	-- register our protocol to handle udp port 24242
	udp_table:add(24242,test_proto)

	-- load the udp.port table
	local tcp_table = DissectorTable.get("tcp.port")
	-- register our protocol to handle tcp port 24242
	tcp_table:add(24242,test_proto)
end
