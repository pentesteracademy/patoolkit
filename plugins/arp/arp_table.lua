--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]


local ARP={}

local util=require('util')
--Dialog menu's for showing ARP tabel in a formatted column format
local function dialog_menu1(win,stringToFind)
		
		local header=  " __________________________________________________________________________________________________\n"
                     .."|  S.no  |        IP         |         MAC         | ARP Packets | Grat ARP packets | ARP spoofing |\n"


		local column_serial_length=8   
		local column_1_length=19        
		local column_2_length=21
		local column_3_length=13
		local column_4_length=18
		local column_5_length=14
   
		win:set(header)
		
		local count=0
		for key,value in pairs(ARP)
		do


			
			--Values to be displayed in the table
			serial=count+1
			column_1_value=value["IP"]     
			column_2_value=value["MAC"]     
			column_3_value=value["ARP Count"]
			column_4_value=value["Grat"]
			column_5_value=value["Spoofing"]
			if(util.searchStr({column_1_value,column_2_value,column_3_value,column_4_value,column_5_value},stringToFind))
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
				["delimiter"]="-",
				["next"]=true
			},
			{ 
				["value"]=column_2_value,
				["length"]=column_2_length,
				["delimiter"]=",",
				["next"]=true
			},
			{ 
				["value"]=column_3_value,
				["length"]=column_3_length,
				["delimiter"]="~",
				["next"]=true
			},                                          
			{ 
				["value"]=column_4_value,
				["length"]=column_4_length,
				["delimiter"]="~",
				["next"]=true
			},    
			{ 
				["value"]=column_5_value,
				["length"]=column_5_length,
				["delimiter"]="~",
				["next"]=true
			}    
			}
			
			win:append("|--------------------------------------------------------------------------------------------------|\n")
			
			win:append(acf(acf_settings,"|"))

		end
		end
		win:append("|__________________________________________________________________________________________________|\n")
end

 function menu1()
  util.dialog_menu(dialog_menu1,"ARP table")
 end

  -- Register the function to Tools menu
  register_menu("ARP/ARP Table",menu1, MENU_TOOLS_UNSORTED)


local function callback_ARP()

	
	--Defining the listeners for ARP
	local arp = Listener.new("frame","arp");
    
	--Defining the fields using which we will infer if packets are ARP packets 	
    local pkt_type = Field.new('eth.type')
	
	local arp_type = Field.new('arp.opcode')
	
	local arp_src_mac = Field.new('arp.src.hw_mac')
	
	local arp_dst_mac = Field.new('arp.dst.hw_mac')
	
	local arp_src_ip = Field.new('arp.src.proto_ipv4')
	
	local arp_dst_ip = Field.new('arp.dst.proto_ipv4')
	
	
	local function getstring(str)
		if(str()~=nil) then return tostring(str()) else return "NA" end
	end
	
	--Function called on each ARP packet	
    function arp.packet(pinfo)
       
	   --Getting the field values for a packet
	   local eth_type = getstring(pkt_type)
	   local arp_pkt_type = getstring(arp_type)
	   local src_mac = getstring(arp_src_mac)
	   local src_ip = getstring(arp_src_ip)
	   local dst_mac = getstring(arp_dst_mac)
	   local dst_ip =getstring(arp_dst_ip)
		
		--Defining the key for each new IP:MAC pair
		local key=src_ip..src_mac
		
		--If there is no entry in the table, make one
		if(ARP[key] == nil) then
			
				ARP[key]={}
				ARP[key]["Spoofing"] = "No"
				ARP[key]["Grat"] = 0
				
				--Check if the src IP is associated with some other MAC
				--If that be the case, then there is a possible ARP 
				--spoof done.
				--Also check if the src MAC is associated with some other IP
				for k,v in pairs(ARP)
				do
					if( src_ip == v["IP"] or src_mac == v["MAC"] ) then
						ARP[key]["Spoofing"] = "Yes"
						v["Spoofing"] = "Yes"
					end
				end
				
				--creating entries
				ARP[key]["IP"]=src_ip
				ARP[key]["MAC"]=src_mac
				ARP[key]["ARP Count"]=1
				
				--Checking if the packet is a Gratuitous ARP packet
				if((src_ip == dst_ip) and (dst_mac == "ff:ff:ff:ff:ff:ff")) then
					ARP[key]["Grat"] =ARP[key]["Grat"] + 1
				end	
		--If there is already an entry, increment the counters of 
		--specific packets
		else
			ARP[key]["ARP Count"]=ARP[key]["ARP Count"]+1
			
			if((src_ip == dst_ip) and (dst_mac == "ff:ff:ff:ff:ff:ff")) then
				ARP[key]["Grat"]=ARP[key]["Grat"]+1
			end
		end
    end
end


local function Main()
    callback_ARP()
end
Main()

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
