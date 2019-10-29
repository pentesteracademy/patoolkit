--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]


do
  if not gui_enabled() then return end

    local util=require('util')
    local security=require('security')

    local Bssid=Field.new("wlan.bssid")
    local Ssid=Field.new("wlan.ssid")
    local Channel=Field.new("wlan.ds.current_channel")
    local fc_type=Field.new("wlan.fc.type")
    local sub_type=Field.new("wlan.fc.type_subtype")
    local frame_length=Field.new("frame.len")
    local frame_number=Field.new("frame.number")
    local wlan_addr=Field.new("wlan.addr")
    
    local ssids={}
    local ssids_store={}
    function getString(str)
        if(str~=nil) then return tostring(str) else return "NA" end
    end

    local tap = Listener.new("frame", "wlan")

    -- Called at the end of live capture run
    function tap.reset()
      ssids= {}
      ssids_store={}
    end

    -- Called at the end of the capture to print the summary
    function tap.draw()

    end
    local count=1

    -- Called once each time the filter of the tap matches
    function tap.packet(pinfo, tvb)

        local bssid=getString(Bssid())
        local type=getString(fc_type())
        
        -- check whether bssid exists and is not equal to brodcast
        if(bssid~="" and bssid~="ff:ff:ff:ff:ff:ff")
            then

            -- check whether this bssid has been encountered before, if not then create a entry in table
            if(ssids[bssid]==nil and bssid~="")
                then

                table.insert(ssids_store,bssid)
                ssids[bssid]={}
                ssids[bssid]["controlCount"]=0
                ssids[bssid]["mgmtCount"]=0
                ssids[bssid]["dataCount"]=0
                ssids[bssid]["addr-bssid-same"]=0
            end


            -- for % packet, check
            if(getString(wlan_addr())==bssid)
                then

                -- for % packets, when bssid==wlan.addr
                ssids[bssid]["addr-bssid-same"]=ssids[bssid]["addr-bssid-same"]+1
            end

            -- for managment frame
            if(type=="0")
                then
                ssids[bssid]["mgmtCount"]=ssids[bssid]["mgmtCount"]+1

                -- if becaon frame is found update rest of the information
                if(getString(sub_type())=="8")
                    then

                    if(ssids[bssid]["ssid"]==nil)
                        then

                        -- get encryption, key mangment and wps state from here
                        local gc,pc,keyM,enc,wpa_st,frame_pr=security.getEncryption()
                        ssids[bssid]["ssid"]=getString(Ssid())
                        ssids[bssid]["channel"]=getString(Channel())
                        ssids[bssid]["enc"]=enc
                        ssids[bssid]["keyM"]=keyM
                        ssids[bssid]["wps"]=wpa_st
                    end
                end

    --[[    elseif(type=="1")
                then
                ssids[bssid]["controlCount"]=ssids[bssid]["controlCount"]+1
    --]]

            -- increment in case of data frame
            elseif(type=="2")
                then
                ssids[bssid]["dataCount"]=ssids[bssid]["dataCount"]+1
            end
        end
    end

        local function security_information(win,stringToFind)

          
            local header=  " ______________________________________________________________________________________________________________________________________________________\n"
                         .."|   S.no   |      SSID      |       BSSID       | Channel | Data Count | Managment Count | % Packets |      Security       |  Key Managment  |   WPS   |\n"
           
            win:set(header)
            local count=0
            for t,k in ipairs(ssids_store)do           -- <- table whoes data you wana print
                  
                  data=ssids[k]
                    if(data["ssid"]~=nil)
                        then
                          if(util.searchStr({data["ssid"],k,data["channel"],data["dataCount"],data["mgmtCount"],data["enc"],data["keyM"],data["wps"],string.format("%.2f",(data["addr-bssid-same"]/(data["mgmtCount"]+data["dataCount"]+data["controlCount"]))*100)},stringToFind))
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
                                ["value"]=data["ssid"],
                                ["length"]=16,
                                ["delimiter"]="",
                                ["next"]=true,
                                ["branch"]=false
                              },
                              { 
                                ["value"]=k,
                                ["length"]=19,
                                ["delimiter"]="",
                                ["next"]=true,
                                ["branch"]=false
                              },
                              { 
                                ["value"]=data["channel"],
                                ["length"]=9,
                                ["delimiter"]=",",
                                ["next"]=true,
                                ["branch"]=false
                              },
                              { 
                                ["value"]=data["dataCount"],
                                ["length"]=12,
                                ["delimiter"]=",",
                                ["next"]=true,
                                ["branch"]=false
                              },
                            --[[  { 
                                ["value"]=data["controlCount"],
                                ["length"]=15,
                                ["delimiter"]=",",
                                ["next"]=true,
                                ["branch"]=false
                              },--]]
                              { 
                                ["value"]=data["mgmtCount"],
                                ["length"]=17,
                                ["delimiter"]=",",
                                ["next"]=true,
                                ["branch"]=false
                              },
                              { 
                                ["value"]=string.format("%.2f",(data["addr-bssid-same"]/(data["mgmtCount"]+data["dataCount"]+data["controlCount"]))*100),
                                ["length"]=11,
                                ["delimiter"]=",",
                                ["next"]=true,
                                ["branch"]=false
                              },
                              { 
                                ["value"]=data["enc"],
                                ["length"]=21,
                                ["delimiter"]=",",
                                ["next"]=true,
                                ["branch"]=false
                              },
                              { 
                                ["value"]=data["keyM"],
                                ["length"]=17,
                                ["delimiter"]=",",
                                ["next"]=true,
                                ["branch"]=false
                              },
                              { 
                                ["value"]=data["wps"],
                                ["length"]=9,
                                ["delimiter"]=",",
                                ["next"]=true,
                                ["branch"]=false
                              }                                   
                            }
                              win:append("|------------------------------------------------------------------------------------------------------------------------------------------------------|\n")        
                              win:append(acf(acf_settings,"|"))  
                          end
                        end
                  end
          win:append("|______________________________________________________________________________________________________________________________________________________|\n")     

        end 

        function menu1()
          util.dialog_menu(security_information,"Overview")
        end

        register_menu("WiFi/Overview",menu1, MENU_TOOLS_UNSORTED)



end


------------------------------------------------------------ Function For String Formatting START----------------------------------

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
    local flag=false


    if(str:len()<=len)
        then
        flag=true
    end

    if(global["branch"])
        then
        if(str:find(delimiter)~=nil)
            then
            flag=false
        end
    end
    if(flag)
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

    else
        local str2=""
        local a=len
        if(delimiter~="")
          then
            if(global["branch"]) then str2=delimiter else str2=""..delimiter.."[^"..delimiter.."]*$" end
            a=string.find(str:sub(0,len), str2)
        end
        local c=0
        if(a==nil or a>=len) then a=len else c=1 end
        global["value"]=str:sub(a+c)
        global["next"]=true

      
        return format_str(global,str:sub(1,a-1))
    end
    return s
end
------------------------------------------------------------ Function For String Formatting END----------------------------------                    
