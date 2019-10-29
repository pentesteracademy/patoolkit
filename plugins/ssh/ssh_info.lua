--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]


do
  if not gui_enabled() then return end

        local util=require('util')
        local frame_number=Field.new("frame.number")
        local src=Field.new("ip.src")
        local ipv6src=Field.new("ipv6.src")
        local ipv6dst=Field.new("ipv6.dst")
        local dst=Field.new("ip.dst")
        local src_port=Field.new("tcp.srcport")
        local dst_port=Field.new("tcp.dstport")
        local ssh_message_code=Field.new("ssh.message_code")
        local enc_client_server=Field.new("ssh.encryption_algorithms_client_to_server")
        local enc_server_client=Field.new("ssh.encryption_algorithms_server_to_client")
        local mac_server_client=Field.new("ssh.mac_algorithms_client_to_server")
        local mac_client_server=Field.new("ssh.mac_algorithms_server_to_client")
        local comp_server_client=Field.new("ssh.compression_algorithms_client_to_server")
        local comp_client_server=Field.new("ssh.compression_algorithms_server_to_client")
        local ssh_protocol=Field.new("ssh.protocol")
        local sc={}
        local container={}

        local function getString(str)
            if(str~=nil) then return tostring(str) else return "NA" end
        end

        function getFrame()
            return tostring(frame_number())
        end

        function getSource()
          if (src_port() and (src() or ipv6src()))
            then
                return tostring(src() or ipv6src())..":"..tostring(src_port())
          else
                return "NA"
          end
        end

        function getDestination()
          if (dst_port() and (dst() or ipv6dst()))
            then
            return tostring(dst() or ipv6dst())..":".. tostring(dst_port())
          else
            return "NA"
          end
        end

local function init_listener()

    local tap = Listener.new("frame", "ssh")

    -- Called at the end of live capture run
    function tap.reset()
      container= {}
      sc={}
    end

    -- Called at the end of the capture to print the summary
    function tap.draw()

    end

    -- Called once each time the filter of the tap matches
    function tap.packet(pinfo, tvb)
        if (getSource() ~= "NA" and container[getSource()]==nil and ssh_protocol()~=nil)
          then
            local info={}
            -- get the protocol information
            local protocol=getString(ssh_protocol())
            protocol=string.sub(protocol,5)
            -- split the field to get useragent, version and operating system
            -- the field is in format of "SSH-2.0-OpenSSH_7.7 Ubuntu"
            local pos=string.find(protocol,"-")
            if pos==nil then pos=string.len(protocol)+1 end
            info["ip"]=getString(src() or ipv6src())
            info["version"]=string.sub(protocol,1,pos-1)
            local last=string.find(protocol," ")
            if(last~=nil)
              then
                info["user_agent"]=string.sub(protocol,pos+1,last-1)
                info["os"]=string.sub(protocol,last+1)
            else
                info["user_agent"]=string.sub(protocol,pos+1)
                info["os"]=""
            end

            container[getSource()]=info

        -- check key exchange init to get the algorithms for both server and clients
        elseif(getString(ssh_message_code()) == "20")
          then

                local pair={}
               
                pair["enc_server_client"]=split(getString(enc_server_client()),",")
                pair["enc_client_server"]=split(getString(enc_client_server()),",")
                pair["mac_server_client"]=split(getString(mac_server_client()),",")
                pair["mac_client_server"]=split(getString(mac_client_server()),",")
                pair["comp_server_client"]=split(getString(comp_server_client()),",")
                pair["comp_client_server"]=split(getString(comp_client_server()),",")

                sc[getSource()]=pair
                if(sc[getDestination()]~=nil)
                  then

                    local other=sc[getDestination()]
                    local enc_s_c=""
                    local enc_c_s=""
                    local mac_s_c=""
                    local mac_c_s=""
                    local comp_s_c=""
                    local comp_c_s=""
                    local type=""

                    -- client is proritized for choosing algorithm, match function is used to iterate over strings and find the one
                    -- the one that matches first from parameter one among values in parameter 2
                    -- pair holds the value from current packet, if the current packet is from server, the values will be passed as second 
                    -- parameters, first parameter will contain values of client
                    if(getString(src_port())=="22")
                      then
                        type="server"
                        enc_s_c=match(other["enc_server_client"],pair["enc_server_client"])
                        enc_c_s=match(other["enc_client_server"],pair["enc_client_server"])
                        mac_s_c=match(other["mac_server_client"],pair["mac_server_client"])
                        mac_c_s=match(other["mac_client_server"],pair["mac_client_server"])
                        comp_s_c=match(other["comp_server_client"],pair["comp_server_client"])
                        comp_c_s=match(other["comp_client_server"],pair["comp_client_server"])
                    else

                        -- if the source is client, the current values are passed as first parameter.
                        type="client"
                        enc_s_c=match(pair["enc_server_client"],other["enc_server_client"])
                        enc_c_s=match(pair["enc_client_server"],other["enc_client_server"])
                        mac_s_c=match(pair["mac_server_client"],other["mac_server_client"])
                        mac_c_s=match(pair["mac_client_server"],other["mac_client_server"])
                        comp_s_c=match(pair["comp_server_client"],other["comp_server_client"])
                        comp_c_s=match(pair["comp_client_server"],other["comp_client_server"])
                    end

                    local current=container[getSource()]
                    local prev=container[getDestination()]

                    -- if client server encryption, mac and compression are different from server client enc, mac and compression
                    -- store the values seperated by commas
                    if(enc_c_s==enc_s_c) then
                      current["encryption"]=enc_s_c
                      prev["encryption"]=enc_s_c
                    else
                      current["encryption"]=enc_s_c..","..enc_c_s
                      prev["encryption"]=enc_s_c..","..enc_c_s
                    end

                    if(mac_c_s==mac_s_c)then
                      current["mac"]=mac_s_c
                      prev["mac"]=mac_s_c
                    else
                      current["mac"]=mac_s_c..","..mac_c_s
                      prev["mac"]=mac_s_c..","..mac_c_s
                    end

                    if(comp_c_s==comp_s_c)then
                      current["compression"]=comp_s_c
                      prev["compression"]=comp_s_c
                    else
                      current["compression"]=comp_s_c..","..comp_c_s
                      prev["compression"]=comp_s_c..","..comp_c_s
                    end
                    current["type"]=type
                    container[getSource()]=current
                    container[getDestination()]=prev
                end
             end
        
    end
end

    
        local function get_ssh(win,stringToFind)
            local header=  " __________________________________________________________________________________________________________________________________\n"
                         .."|   S.no   |     IP Address     |       User Agent     | Operating System | Version |    Encryption    |     MAC    |  Compression |\n"
            win:set(header)
            local count=0
            for k,v in pairs(container)do           -- <- table whoes data you want print

            if(util.searchStr({v["ip"],v["user_agent"],v["os"],v["version"],v["encryption"],v["mac"],v["compression"]},stringToFind))
                then

                    count=count+1


                  local acf_settings={
                  { 
                    ["value"]=count,           
                    ["length"]=10,  
                    ["delimiter"]="",                 
                    ["next"]=true,
                    ["branch"]=false                     
                  },
                  { 
                    ["value"]=v["ip"],
                    ["length"]=20,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=v["user_agent"],
                    ["length"]=22,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=v["os"],
                    ["length"]=18,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=true
                  },
                  { 
                    ["value"]=v["version"],
                    ["length"]=9,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=true
                  },
                  { 
                    ["value"]=v["encryption"],
                    ["length"]=18,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=true
                  },
                  { 
                    ["value"]=v["mac"],
                    ["length"]=12,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=true
                  },
                  { 
                    ["value"]=v["compression"],
                    ["length"]=14,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=true
                  },                                  
                }
                  win:append("|----------------------------------------------------------------------------------------------------------------------------------|\n")  
                  
                  win:append(acf(acf_settings,"|"))  
                end
          end
          win:append("|__________________________________________________________________________________________________________________________________|\n")     

        end 

        local function get_vuln(win,stringToFind)
            local header=  " ___________________________________________________________________________________\n"
                         .."|   S.no   |     IP Address     |       User Agent     | Operating System | Version |\n"
            win:set(header)
            local count=0
            for k,v in pairs(container)do           -- <- table whoes data you want print
            if(tonumber(v["version"])<2.0)
              then
              if(util.searchStr({v["ip"],v["user_agent"],v["os"],v["version"],v["encryption"],v["mac"],v["compression"]},stringToFind))
                  then
                    
                    count=count+1

                    local acf_settings={
                    { 
                      ["value"]=count,           
                      ["length"]=10,  
                      ["delimiter"]="",                 
                      ["next"]=true,
                      ["branch"]=false                     
                    },
                    { 
                      ["value"]=v["ip"],
                      ["length"]=20,
                      ["delimiter"]=",",
                      ["next"]=true,
                      ["branch"]=false
                    },
                    { 
                      ["value"]=v["user_agent"],
                      ["length"]=22,
                      ["delimiter"]=",",
                      ["next"]=true,
                      ["branch"]=false
                    },
                    { 
                      ["value"]=v["os"],
                      ["length"]=18,
                      ["delimiter"]=",",
                      ["next"]=true,
                      ["branch"]=true
                    },
                    { 
                      ["value"]=v["version"],
                      ["length"]=9,
                      ["delimiter"]=",",
                      ["next"]=true,
                      ["branch"]=true
                    }                                
                  }
                    win:append("|-----------------------------------------------------------------------------------|\n")  
                    
                    win:append(acf(acf_settings,"|"))  
                  end
            end
          end
          win:append("|___________________________________________________________________________________|\n")     

        end 

        function menu1()
            util.dialog_menu(get_ssh,"SSH Information")
        end

        function menu2()
            util.dialog_menu(get_vuln,"Vulnerable SSH Versions")
        end

        register_menu("SSH/SSH Information",menu1, MENU_TOOLS_UNSORTED)
        register_menu("SSH/Vulnerable Version",menu2, MENU_TOOLS_UNSORTED)


  init_listener()

end
        function split(inputstr, sep)
            if sep == nil then
                    sep = "%s"
            end
            local t={} ; i=1
            for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
                    t[i] = str
                    i = i + 1
            end
            return t
        end

        function match(t1,t2)
          for k,v in pairs(t1)do
            for k2,v2 in pairs(t2)do
              if(v==v2)then
                return v2
              end
            end
          end
        end

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
                local str2=""
                if(global["branch"]) then str2=""..delimiter.."[^"..delimiter.."]" else str2=""..delimiter.."[^"..delimiter.."]*$" end

                local a=string.find(str:sub(0,len), str2)
                local c=0
                if(delimiter=="" or a==nil or a>len) then a=len else c=1 end
                global["value"]=str:sub(a+c)
                global["next"]=true
                return format_str(global,str:sub(1,a-1))
            end
            return s
        end
