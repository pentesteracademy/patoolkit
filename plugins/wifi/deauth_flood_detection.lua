--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]

-- proto object


do
  if not gui_enabled() then return end

  local util=require('util')

        local data_after_deauth_threshold=30
        local de = Proto("de","Deauth/Diassoc Flood Detector")

        local wlan=Field.new("wlan")
        local sub_type=Field.new("wlan.fc.type_subtype")
        local wlan_sa=Field.new("wlan.sa")
        local wlan_da=Field.new("wlan.da")
        local time=Field.new("frame.time_relative")
        local data=Field.new("data")

        local function getString(str)
            if(str~=nil) then return tostring(str) else return "NA" end
        end

        local container_store={}

        local container={}

        function getType()
            return getString(sub_type())
        end

        function getTime()
            return tonumber(tostring(time() or "0"))
        end


local function init_listener()

    local tap = Listener.new("frame", "wlan")

    -- Called at the end of live capture run
    function tap.reset()
      container= {}
      container_store={}
    end

    -- Called once each time the filter of the tap matches
    function tap.packet(pinfo, tvb)
           if(wlan()~=nil and wlan_sa()~=nil and wlan_da()~=nil)
           then
                local sa=getString(wlan_sa())
                local da=getString(wlan_da())

                -- check whether the packet is disassoc or deauth
                if(getType()=='12' or getType()=='10')
                    then

                        -- if an entry already exists for the connection, swap addresses
                        if(container[da..sa]~=nil)
                            then
                             da=getString(wlan_sa())
                             sa=getString(wlan_da())
                        end

                        -- if this is the first time, initalize the array with source, destination and other values
                        if(container[sa..da]==nil)
                            then

                            table.insert(container_store,sa..da)
                            local data={}
                            data["source"]=sa
                            data["destination"]=da
                            data["data"]=false
                            data["deAuthTotal"]=0
                            data["disAssocTotal"]=0
                            if(getType()=='12')
                                then
                                data["deAuthCount"]=1
                                data["disAssocCount"]=0
                                data["deAuthTimeStart"]=getTime()
                                data["deAuthTimeStop"]=getTime()
                                data["deAuthAvg"]=0
                                data["deAuthAvgCount"]=0
                                data["disAssocTimeStart"]=0
                                data["disAssocTimeStop"]=0
                                data["disAssocAvg"]=0
                                data["disAssocAvgCount"]=0
                                data["last"]="DeAuth"
                            else
                                data["deAuthCount"]=0
                                data["disAssocCount"]=1
                                data["disAssocTimeStart"]=getTime()
                                data["disAssocTimeStop"]=getTime()
                                data["deAuthAvg"]=0
                                data["deAuthAvgCount"]=0
                                data["deAuthTimeStart"]=0
                                data["deAuthTimeStop"]=0
                                data["disAssocAvg"]=0
                                data["disAssocAvgCount"]=0
                                data["last"]="Disassoc"
                            end
                            container[sa..da]=data
                        
                        -- otherwise, update the existing entry
                        else

                           local data=container[sa..da]

                            -- if the packet is deauth 
                            if(getType()=='12')
                                then

                                -- if last packet was data, the deauth count is 1
                                if(data["last"]=="Data")
                                    then
                                    data["deAuthAvg"]=math.max(data["deAuthAvg"],data["deAuthCount"]/div(data["deAuthTimeStop"],data["deAuthTimeStart"]))
                                    data["deAuthTotal"]=data["deAuthTotal"]+data["deAuthCount"]
                                    data["deAuthCount"]=1
                                    data["deAuthTimeStart"]=getTime()
                                else
                                    -- if the last packet was not data packet increment deauth by 1
                                    data["deAuthCount"]=data["deAuthCount"]+1
                                end

                                -- initialize deauthTime 
                                if(data["deAuthTimeStart"]==0)
                                    then
                                    data["deAuthTimeStart"]=getTime()
                                end
                                data["deAuthTimeStop"]=getTime()

                                -- mark last packet as deauth
                                data["last"]="DeAuth"

                            -- similiarly for disassoc
                            else

                                -- if the last packet was data packet initialize deauth count with 1
                                if(data["last"]=="Data")
                                    then
                                    data["disAssocAvg"]=math.max(data["disAssocCount"]/div(data["disAssocTimeStop"],data["disAssocTimeStart"]))
                                    data["disAssocTotal"]=data["disAssocTotal"]+data["disAssocCount"]
                                    data["disAssocCount"]=1
                                    data["disAssocTimeStart"]=getTime()
                                else

                                    data["disAssocCount"]=data["disAssocCount"]+1
                                end
                                if(data["disAssocTimeStart"]==0)
                                    then
                                    data["disAssocTimeStart"]=getTime()
                                end
                                data["disAssocTimeStop"]=getTime()
                                data["last"]="DeAuth"
                            end
                           container[sa..da]=data
                              
                        end

                -- for data packet
                elseif(container[sa..da]~=nil and data()~=nil)
                    then
                    container[sa..da]["last"]="Data"
          
                    -- check after how long the data packet was sent, if its less than the threshold then it is probably a deauth attack.
                    if(getTime()-math.max(container[sa..da]["deAuthTimeStop"],container[sa..da]["disAssocTimeStop"]) < data_after_deauth_threshold)
                        then
                        container[sa..da]["data"]=true
                    end

                end


           end  
        end



    end

        local function deauth_disassoc_flooding(win,stringToFind)
            local header=  " _____________________________________________________________________________________________\n"
                         .."|   S.no   |       Source       |       Target       |               Statistics               |\n"



           
            win:set(header)
            local count=0
            for k,value in ipairs(container_store)do           -- <- table whoes data you wana print
                v=container[value]

              
            local str="Deauth Count: "
                    ..getString(v["deAuthTotal"]+v["deAuthCount"])
                    ..",Deauth per sec: "
                    .. getString(math.max(v["deAuthAvg"],(v["deAuthCount"]/div(v["deAuthTimeStop"],v["deAuthTimeStart"]))))
                    ..",DisAssoc Count: "
                    ..getString(v["disAssocTotal"]+v["disAssocCount"])
                    ..",DisAssoc per sec: "
                    .. getString(math.max(v["disAssocAvg"],(v["disAssocCount"]/div(v["disAssocTimeStop"],v["disAssocTimeStart"]))))
                    ..",Data after Deauth/Disassoc: ".. getString(v["data"])

            if(util.searchStr({str,v["source"],v["destination"]},stringToFind))
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
                    ["value"]=v["source"],
                    ["length"]=20,
                    ["delimiter"]="",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=v["destination"],
                    ["length"]=20,
                    ["delimiter"]="",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=str,
                    ["length"]=40,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=true
                  }                                  
                }
                  win:append("|---------------------------------------------------------------------------------------------|\n")  
                  
                  win:append(acf(acf_settings,"|"))  
                end
          end
          win:append("|_____________________________________________________________________________________________|\n")     

        end 


        function menu1()
            util.dialog_menu(deauth_disassoc_flooding,"Deauth Disassoc Flooding")
        end

        register_menu("WiFi/Deauth Disassoc Flooding",menu1, MENU_TOOLS_UNSORTED)


  init_listener()

end

        function div(a,b)
            if(a==b)
                then
                return 1
            else
                return a-b
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

                    