--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]



do
  if not gui_enabled() then return end

        local util=require('util')

        local data_after_deauth_threshold=30
        local wlan_sa=Field.new("wlan.sa")
        local wlan_da=Field.new("wlan.da")
        local key=Field.new("wlan_rsna_eapol.keydes.key_info")
        local frame_number=Field.new("frame.number")
        local replay=Field.new("eapol.keydes.replay_counter")
        local container={}
        local container_store={}
        
        local function getString(str)
            if(str~=nil) then return tostring(str) else return "NA" end
        end

        function getFrame()
            return getString(frame_number())
        end

        function getKey()
            return getString(key())
        end
        function getReplay()
            return getString(replay())
        end


local function init_listener()

    local tap = Listener.new("frame", "eapol.type==3")

    -- Called at the end of live capture run
    function tap.reset()
      container= {}
      container_store={}
    end

    -- Called at the end of the capture to print the summary
    function tap.draw()

    end

    -- Called once each time the filter of the tap matches
    function tap.packet(pinfo, tvb)

        local key_name=""
        local da=""
        local sa=""
        -- get the key and initialize the key_name variable.
        if(getKey()=="0x0000008a")
            then
            key_name="first"
        elseif(getKey()=="0x0000010a")
            then
            key_name="second"
        elseif(getKey()=="0x000013ca")
            then
            key_name="third"
        else
            key_name="fourth"
        end

        -- if the key name is second or fourth, revert the destination and source address, since entry is created
        -- with key as source and destination of station
        if(key_name=="second" or key_name=="fourth") 
        then 
            da=getString(wlan_sa())
            sa=getString(wlan_da())
        else
            sa=getString(wlan_sa())
            da=getString(wlan_da())
        end
        local data={}

        -- initialize if entry doesnt exists
        if(container[sa..da]==nil)
            then
            table.insert(container_store,sa..da)
            local datA={}
            datA["source"]=sa
            datA["destination"]=da
            datA["firstCount"]=0
            datA["secondCount"]=0
            datA["thirdCount"]=0
            datA["fourthCount"]=0
            datA["firstFrames"]={}
            datA["secondFrames"]={}
            datA["thirdFrames"]={}
            datA["fourthFrames"]={}
            datA["firstReplay"]={}
            datA["secondReplay"]={}
            datA["thirdReplay"]={}
            datA["fourthReplay"]={}    
            container[sa..da]=datA
        end

            -- get the frame number and replay counter and store it into corresponding key store,
            -- there might be multiple key, thats why a store is being maintained. 
            data=container[sa..da]
            data[key_name.."Count"]=data[key_name.."Count"]+1
            table.insert(data[key_name.."Frames"],getFrame())
            table.insert(data[key_name.."Replay"],getReplay())


    end
end

        local function handshake_cracking(win,stringToFind)
            
            local header=  " _____________________________________________________________________________________________\n"
                         .."|   S.no   |     Access Point   |       Station      |    Available Hanshakes For Breaking    |\n"



           
            win:set(header)
            local count=0
            for t,k in ipairs(container_store)do           -- <- table whoes data you wana print
                
                data=container[k]

                local flag=false
                --if(data["firstCount"]==1 and data["secondCount"]==1 and data["thirdCount"]==1 and data["fourthCount"]==1 and tonumber(data["firstReplay"])==tonumber(data["secondReplay"]))
                local str="2"
                if(data["secondCount"]~=nil)
                    then
                    local i=1
                    local k=1

                    -- check for the last first key with first second key that have same replay
                    while(i<=data["firstCount"] and k <=data["secondCount"])do
                        if(data["firstFrames"][i]< data["secondFrames"][k])
                            then
                            if(data["firstReplay"][i]==data["secondReplay"][k])
                                then
                                flag=true
                            end
                            i=i+1
                        else
                            k=k+1
                        end
                    end
                    if(flag)then str="1,"..str end
                    i=1
                    k=1
                    flag=false

                    -- similiary match the last second key that matches with first third key and has replay difference of 1

                    while(i<=data["secondCount"] and k <= data["thirdCount"])do
                        if(data["secondFrames"][i]< data["thirdFrames"][k])
                            then

                            if(data["thirdReplay"][k]-data["secondReplay"][i]==1)
                                then
                                flag=true
                            end
                            i=i+1
                        else
                            k=k+1
                        end
                    end
                    if(flag)then str=str..",3" end
                    i=1
                    k=1

                    -- if all three key are already present, check for fourth one in similar fashion as previous ones
                    if(str=="1,2,3")
                        then
                        while(i<=data["thirdCount"] and k <=data["fourthCount"])do
                            if(data["thirdFrames"][i]< data["fourthFrames"][k])
                                then
                                if(data["thirdReplay"][i]==data["fourthReplay"][k])
                                    then
                                    flag=true
                                end
                                i=i+1
                            else
                                k=k+1
                            end
                        end
                        if(flag)then str=str..",4" end
                    end

                end

                -- check if string was modified or not.
                if(str~="2")
                    then
                    
                 
                    if(util.searchStr({data["source"],data["destination"],str},stringToFind))
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
                            ["value"]=data["source"],
                            ["length"]=20,
                            ["delimiter"]="",
                            ["next"]=true,
                            ["branch"]=false
                          },
                          { 
                            ["value"]=data["destination"],
                            ["length"]=20,
                            ["delimiter"]="",
                            ["next"]=true,
                            ["branch"]=false
                          },
                          { 
                            ["value"]=str,
                            ["length"]=40,
                            ["delimiter"]="",
                            ["next"]=true,
                            ["branch"]=false
                          }                                  
                        }
                          win:append("|---------------------------------------------------------------------------------------------|\n")        
                          win:append(acf(acf_settings,"|"))  
                    end
                end
          end
          win:append("|_____________________________________________________________________________________________|\n")     

        end 


        function menu1()
            util.dialog_menu(handshake_cracking,"Possible Handshake Cracking")
        end

        register_menu("WiFi/WPA Cracking Possibility",menu1, MENU_TOOLS_UNSORTED)


  init_listener()

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

                    