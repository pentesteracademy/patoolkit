--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]

local DHCP_Tabel={}
local DHCP_Server={}
local util=require('util')
--Dialog Menu for Displaying Server Details
local function dialog_menu1(win,stringToFind)


		local header=  " ______________________________________________________________________________________________________\n"
                     .."|  S.no  |   Server IP   |       Name       |    Gateway    |      DNS      |     Subnet    | Response |\n"


		local column_serial_length=8   
		local column_1_length=15        
		local column_2_length=18
		local column_3_length=15
		local column_4_length=15
		local column_5_length=15
		local column_6_length=10
   
		win:set(header)
		
		local count=0
		for key,value in pairs(DHCP_Server)
		do
			
			--if(value["ARP Req"] >= 200) then
			
			--Values to be displayed in the table
			serial=count+1
			column_1_value=value["ServerIP"]     
			column_2_value=value["Name"]     
			column_3_value=value["Gateway"]
			column_4_value=value["DNS"]
			column_5_value=value["subnet"]
			column_6_value=value["Res"]
			
			if(util.searchStr({column_1_value,column_2_value,column_3_value,column_4_value,column_5_value,column_6_value},stringToFind))
            then
              count=count+1
			--Defining all the fields to be used in the table
			local acf_settings={
			{ 
				["value"]=serial,           
				["length"]=column_serial_length,  
				["delimiter"]="",                
				["next"]=true                     
			},
			{	 
				["value"]=column_1_value,
				["length"]=column_1_length,
				["delimiter"]="",
				["next"]=true
			},
			{ 
				["value"]=column_2_value,
				["length"]=column_2_length,
				["delimiter"]="",
				["next"]=true
			},
			{ 
				["value"]=column_3_value,
				["length"]=column_3_length,
				["delimiter"]="",
				["next"]=true
			},                                          
			{ 
				["value"]=column_4_value,
				["length"]=column_4_length,
				["delimiter"]="",
				["next"]=true
			},    
			{ 
				["value"]=column_5_value,
				["length"]=column_5_length,
				["delimiter"]="",
				["next"]=true
			},   
			{ 
				["value"]=column_6_value,
				["length"]=column_6_length,
				["delimiter"]="",
				["next"]=true
			}
			}
			
			win:append("|------------------------------------------------------------------------------------------------------|\n")
			
			win:append(acf(acf_settings,"|"))
			--end
		end
		end
		win:append("|______________________________________________________________________________________________________|\n")
end


--Dialog menu for displaying Client details
local function dialog_menu2(win,stringToFind)

		
		local header=  " ___________________________________________________________________________________________________________________\n"
                     .."|  S.no  |        MAC        |       IP       |    Gateway    |      DNS      |  DHCP Server  | Relayed | Duplicate |\n"


		local column_serial_length=8   
		local column_1_length=19        
		local column_2_length=16
		local column_3_length=15
		local column_4_length=15
		local column_5_length=15
		local column_6_length=9
		local column_7_length=11
   
		win:set(header)
		
		local count=0
		for key,value in pairs(DHCP_Tabel)
		do

			
			--Values to be displayed in the table
			serial=count+1
			column_1_value=value["MAC"]     
			column_2_value=value["IP"]     
			column_3_value=value["Gateway"]
			column_4_value=value["DNS"]
			column_5_value=value["Server"]
			column_6_value=value["Relay"]
			column_7_value=value["Duplicate"]
			if(util.searchStr({serial,column_1_value,column_2_value,column_3_value,column_4_value,column_5_value,column_6_value,column_7_value},stringToFind))
            then
              count=count+1
			--Defining all the fields to be used in the table
			local acf_settings={
			{ 
				["value"]=serial,           
				["length"]=column_serial_length,  
				["delimiter"]="",                
				["next"]=true                     
			},
			{	 
				["value"]=column_1_value,
				["length"]=column_1_length,
				["delimiter"]="",
				["next"]=true
			},
			{ 
				["value"]=column_2_value,
				["length"]=column_2_length,
				["delimiter"]="",
				["next"]=true
			},
			{ 
				["value"]=column_3_value,
				["length"]=column_3_length,
				["delimiter"]="",
				["next"]=true
			},                                          
			{ 
				["value"]=column_4_value,
				["length"]=column_4_length,
				["delimiter"]="",
				["next"]=true
			},    
			{ 
				["value"]=column_5_value,
				["length"]=column_5_length,
				["delimiter"]="",
				["next"]=true
			},   
			{ 
				["value"]=column_6_value,
				["length"]=column_6_length,
				["delimiter"]="",
				["next"]=true
			},    
			{ 
				["value"]=column_7_value,
				["length"]=column_7_length,
				["delimiter"]="",
				["next"]=true
			}
			}
			
			win:append("|-------------------------------------------------------------------------------------------------------------------|\n")
			
			win:append(acf(acf_settings,"|"))
		end
		end
		win:append("|___________________________________________________________________________________________________________________|\n")
end

function menu1()
  util.dialog_menu(dialog_menu1,"DHCP Server Details")
 end
 function menu2()
  util.dialog_menu(dialog_menu2,"DHCP Client Table")
 end

function callback_client_table()
	--GUI menu registration
    register_menu("DHCP/DHCP Table",menu2, MENU_TOOLS_UNSORTED)
	register_menu("DHCP/Server Info",menu1, MENU_TOOLS_UNSORTED)
	
	--Defining the listeners for ARP
	local dhcp = Listener.new("frame","dhcp");
	
	--Fields to look for useful information
	local pkt_type = Field.new('dhcp.option.dhcp')
	local client_IP = Field.new('dhcp.ip.your')	
	local server_IP = Field.new('dhcp.ip.server')	
	local relay_IP = Field.new('dhcp.ip.relay')	
	local client_MAC = Field.new('dhcp.hw.mac_addr')	
	local gateway_IP =Field.new('dhcp.option.router')	
	local DNS_IP = Field.new('dhcp.option.domain_name_server')	
	local Server_ID = Field.new('dhcp.option.dhcp_server_id')	
	local source_IP = Field.new('ip.src')	
	local source_MAC = Field.new('eth.src')	
	local name = Field.new('dhcp.option.hostname')	
	local subnet = Field.new('dhcp.option.subnet_mask')
	
	local function getString(str)
		if(str~=nil) then return tostring(str) else return "NA" end
	end
	
	--Function called for each DHCP packet
	function dhcp.packet(pinfo)
		
		dhcp_type = getString(pkt_type())
		client = getString(client_IP())
		MAC = getString(client_MAC())
		server = getString(server_IP())
		relay = getString(relay_IP())
		gateway = getString(gateway_IP())
		DNS = getString(DNS_IP())
		SID = getString(Server_ID())
		src_IP = getString(source_IP())
		src_MAC = getString(source_MAC())
		local_name = getString(name())
		mask = getString(subnet())
		
		--Adding a client table entry in the table if it is a DHCP ACK
		if( dhcp_type == "5" ) then
			local key = client..MAC
			DHCP_Tabel[key]={}
			DHCP_Tabel[key]["Duplicate"] = "No"
			
			--Checking in all the table entries, if there are clients having same MACs
			--with different IPs
			for k,v in pairs(DHCP_Tabel)
			do
				if(MAC == v["MAC"]) then
					DHCP_Tabel[key]["Duplicate"] = "Yes"
					v["Duplicate"] = "Yes"
				end
			end
			
			--Filling in useful information
			DHCP_Tabel[key]["IP"]=client
			DHCP_Tabel[key]["MAC"]=MAC
			DHCP_Tabel[key]["Gateway"]=gateway
			DHCP_Tabel[key]["DNS"]=DNS
			DHCP_Tabel[key]["Server"]=SID
			
			--Detecting if it is a Relayed packet
			if(relay ~= "0.0.0.0") then
				DHCP_Tabel[key]["Relay"] = "Yes"
			else 
				DHCP_Tabel[key]["Relay"] = "No"
			end
		end
		
		--Adding a Server entry if the packet is a DHCP OFFER or DHCP ACK
		if( dhcp_type == "5" or dhcp_type == "2" ) then
			
			local key=SID..src_MAC
			
			--Adding a server entry for new Servers
			if( DHCP_Server[key] == nil ) then
				DHCP_Server[key]={}
				DHCP_Server[key]["ServerIP"] = SID
				DHCP_Server[key]["Name"] = local_name
				DHCP_Server[key]["Gateway"]=gateway
				DHCP_Server[key]["DNS"]=DNS
				DHCP_Server[key]["subnet"]=mask
				DHCP_Server[key]["Res"] = 1
			--Incrementing the counters otherwise
			else
				DHCP_Server[key]["Res"] = DHCP_Server[key]["Res"] + 1
			end
		end	
	end
end				
			
	

callback_client_table()


--Function declarations for displaying data in a column format
function acf(settings,column_seperator)
  local final=""
  while(isNext(settings))do
      for k,v in ipairs(settings)do
          if(v["next"]==false) then v["value"]="" else v["next"]=false end
          final=final..column_seperator..format_str(v)
          if(k==#settings) then final=final..column_seperator.."\n" end
      end
   end
  return final
end

function isNext(settings)
  for k,v in ipairs(settings)do 
    if(v["next"]) then return true end
  end
  return false
end

function format_str(global,substr)
    local m=0
    local n=0
    local str=""
    local len=global["length"]
    local delimiter=global["delimiter"]
    if(substr==nil) then str=global["value"] else str=substr end
    if(str==nil) then str="" else str=tostring(str) end
    if (len==nil) then len=0 end
    if(delimiter==nil) then delimiter="" end
    local s=str
    if(str:len()<len)
        then
        if((len-str:len())%2==0)
            then 
                m=(len-str:len())/2
                n=m
        else
                m=math.floor(((len-str:len()) /2))+1
                n=m-1
        end     
        for i=1, m
            do
            s=" "..s
        end
        for i=1, n
            do
            s=s.." "
        end
    elseif(str:len()>len)
        then
        local a=string.find(str:sub(0,len), ""..delimiter.."[^"..delimiter.."]*$")
        local c=0
        if(delimiter=="" or a==nil or a>len) then a=len else c=1 end
        global["value"]=str:sub(a+c)
        global["next"]=true
        return format_str(global,str:sub(1,a-1))
    end
    return s
end
