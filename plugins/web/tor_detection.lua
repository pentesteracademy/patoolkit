--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]

--Some global variable declarations
do
	local util=require('util')
	local src = Field.new('ip.src')
	local dst = Field.new('ip.dst')
	local sni = Field.new('tls.handshake.extensions_server_name')
	local cname = Field.new('x509sat.uTF8String')
	local srcport = Field.new('tcp.srcport')
	local dstport = Field.new('tcp.dstport')
	local proto = Field.new('ip.proto')
	local time=Field.new("frame.time_relative")
	local output = {}
	local store={}

	local function getstring(str)
		if(str()~=nil) then return tostring(str()) else return "NA" end
	end
	
	local function init_listener()

	local tap = Listener.new("frame", "(tls or tcp) && ip")

	    -- Called at the end of live capture run
	function tap.reset()
      output = {}
      store={}
	end

	    -- Called at the end of the capture to print the summary
    function tap.draw()

    end

	function tap.packet(pinfo, tvb)
	    	   --Getting the field values for a packet
		   local src_ip = src()
	           local dst_ip = dst()
		   local s_name = sni()
		   local c_name = cname()
		   local sport = srcport()
		   local dport = dstport()
		   local transport_proto = proto()
		   
		   --Adding the protocol header to the main tree
		  -- local subtree = tree:add(protocol, 'Tor_detection')
		   
		   --Analyzing all TCP packets TO DO : filter out all non-interested fields
		   if getString(transport_proto)=="6" then
		   local flag=false
		   local ip=""
		   local url=""
		   local packets_exchanged=0
		   local data_exchanged=0
		   local sname=""
			--Seeing if the sport or dport is 9001
			if getString(sport) == "9001" then
		
				url=getString(src_ip)
				ip=getString(dst_ip)
				flag=true
			elseif getString(dport) == "9001" then
				url=getString(dst_ip)
				ip=getString(src_ip)
				flag=true
			
			--Checking all the TLS packets(specifically the Client and Server hello)
			elseif getString(sport) == "443" or getString(dport) == "443" then
				--Checking and storing the server name in Client Hello
				if c_name == nil and s_name ~= nil then
					sname = getString(s_name)
				elseif s_name == nil and c_name ~= nil and store[getString(src_ip)]~=nil then
					if store[getString(src_ip)]["server"] == getString(dst_ip) and store[getString(src_ip)]["sname"]~= getString(c_name) then
						url=getString(src_ip)
						ip=getString(dst_ip)
						flag=true
					end
				end

				if(sname~="")
					then
					if(store[getString(dst_ip)]==nil) then
						store[getString(dst_ip)]={}
					end
					store[getString(dst_ip)]["server"]=getstring(src_ip)
					store[getString(dst_ip)]["server"]=sname
				end
			end

			if(flag)
				then
				if(output[ip]==nil or output[ip][url]==nil)
					then
						if(output[ip]==nil)then
							output[ip]={}
						end
						output[ip][url]={
						["data"]=tonumber(tvb:len()),
						["packet"]=1,
						["time"]=tonumber(tostring(time() or "0"))

					}
						
				else
					if(output[ip][url]==nil)then output[ip][url]={}end 

					output[ip][url]["data"]=output[ip][url]["data"]+tonumber(tvb:len())
					output[ip][url]["packet"]=output[ip][url]["packet"]+1
					output[ip][url]["time"]=tonumber(tostring(time() or "0"))
				
				end
			end
		   
		   end
	    end
	    
	end

	local function dialog_menu(win,stringToFind)
	    local col_serial_len=12
	    local column_1_length=25
	    local column_2_length=28
	    local column_3_length=21
	    local column_4_length=12
	    local count=0

	    
	    -- Prints a pretty output of the data analysed so far
	    win:set("")
	    for ip, val in pairs(output) do
	      win:append("Client: ".. ip.."\n")
	      win:append(" ______________________________________________________________________________________________________\n")
	      win:append("|    S.NO    |         Relay IP        |      Packets exchanged     |   Data exchanged    |  Duration  |\n")
	      local count=0
	      for url, tbl in pairs(val) do
	      	local global={tostring(count),false}
	          local global1={url,false}
	      	  if(util.searchStr({global1[1],tostring(tbl["packet"]),tostring(tbl["data"]),tostring(tbl["time"])},stringToFind))
                then

                    count=count+1
	          win:append("|------------------------------------------------------------------------------------------------------|\n")
	          
	          win:append("|"..format_str(global[1],col_serial_len,global,"").."|"..format_str(global1[1],column_1_length,global1,",").."|"..format_str(tostring(tbl["packet"]),column_2_length,global," ").."|"..format_str(tostring(tbl["data"]),column_3_length,global," ").."|"..format_str(tostring(tbl["time"]),column_4_length,global," ").."|\n")
	          while(global1[2]) do
	              win:append("|"..format_str("",col_serial_len,global," "))
	            if(global1[2])
	              then
	              global1[2]=false
	              win:append("|"..format_str(global1[1],column_1_length,global1," "))
	            else
	              win:append("|".. format_str("",column_1_length,global1," "))
	            end
	              win:append("|".. format_str("",column_2_length,global2," "))
	              win:append("|".. format_str("",column_3_length,global,","))
	              win:append("|".. format_str("",column_4_length,global,","))
	              win:append("|".. format_str("",column_5_length,global," ").."|\n")
	          end
	      end
	  end
	         win:append("|______________________________________________________________________________________________________|\n\n")
	    end

	 


	end

	function menu1()
	    util.dialog_menu(dialog_menu,"List of Relays")
	end
  register_menu("Web/TOR Detection",menu1, MENU_TOOLS_UNSORTED)
  init_listener()

end


	function format_str(str,len,global, delimiter)
	    local s=str
	    -- left space variable
	    local m=0
	    -- right space variable 
	    local n=0
	    -- checking if the length is greater than column length

	    if(str:len()<len)
	        then
	        -- checking if legth is devisible by two and adjusting left and right spacing accordingly
	        if((len-str:len())%2==0)
	            then 
	                m=(len-str:len())/2
	                n=m
	        else
	                m=math.floor(((len-str:len()) /2))+1
	                n=m-1
	        end     
	        -- incase ip address is of 14 character append an extra space to manage
	        -- adding left space to string
	        for i=1, m
	            do
	            s=" "..s
	        end
	        -- adding right space to string
	        for i=1, n
	            do
	            s=s.." "
	        end
	    -- incase there are so many domains that the column is filled
	    elseif(str:len()>len)
	        then
	        -- looking for comma to break the domain
	        
	        local a=string.find(str:sub(0,len), ""..delimiter.."[^"..delimiter.."]*$")
	        if(delimiter=="" or a==nil or a>len)
	          then
	          a=len
	        end
	        -- setting remaining string as global to append it later
	        global[1]=str:sub(a)
	        global[2]=true

	        -- returning the string with decreased length
	        return format_str(str:sub(0,a-1),len)
	        
	    end
	    return s
	end