--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]


do
  if not gui_enabled() then return end

        local util=require('util')
        local frame_number=Field.new("frame.number")
        local request_method=Field.new("http.request.method")
        local host=Field.new("http.host")
        local request_uri=Field.new("http.request.uri")
        local user_agent=Field.new("http.user_agent")
        local form_key=Field.new("urlencoded-form.key")
        local form_value=Field.new("urlencoded-form.value")

        local function getString(str)
          if(str~=nil) then return tostring(str) else return "NA" end
        end

        function post()
                return getString(request_method())=="POST"
        end

        local container={}

local function init_listener()

    local tap = Listener.new("frame", "http.request")

    -- Called at the end of live capture run
    function tap.reset()
      container= {}
    end



    -- Called at the end of the capture to print the summary
    function tap.draw()

    end

    -- Called once each time the filter of the tap matches
    function tap.packet(pinfo, tvb)

        -- check if the request is post 
        if post()
          then
            local uri=getString(request_uri())
            local req={}

            -- store the host, useragent and path
            req["host"]=getString(host())
            req["user_agent"]=getString(user_agent())
            req["path"]=uri

            local key={form_key()}
            local value={form_value()}
            req["param"]=""

            -- iterate over the key value pairs and create a string mapping
            for k,v in ipairs(key)do
              req["param"]=req["param"]..getString(v) .. ": " .. getString(value[k])..","
            end
            table.insert(container,req)
        end
    end
end

    
        local function get_request(win,stringToFind)
            local header=  " ______________________________________________________________________________________________________________________\n"
                         .."|   S.no   |       Host       |       User Agent       |              Path              |           Parameter          |\n"



           
            win:set(header)
            local count=0
            for k,v in ipairs(container)do           -- <- table whoes data you want print

              v["param"]=string.sub(v["param"],1,v["param"]:len()-1)

            if(util.searchStr({v["host"],v["user_agent"],v["path"],v["param"]},stringToFind))
                then

                    count=count+1


                  local acf_settings={
                  { 
                    ["value"]=count,           
                    ["length"]=10,  
                    ["delimiter"]=",",                 
                    ["next"]=true,
                    ["branch"]=false                     
                  },
                  { 
                    ["value"]=v["host"],
                    ["length"]=18,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=v["user_agent"],
                    ["length"]=24,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=v["path"],
                    ["length"]=32,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=v["param"],
                    ["length"]=30,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=false
                  }                                  
                }
                  win:append("|----------------------------------------------------------------------------------------------------------------------|\n")  
                  
                  win:append(acf(acf_settings,"|"))  
                end
          end
          win:append("|______________________________________________________________________________________________________________________|\n")     

        end 


        function menu1()
            util.dialog_menu(get_request,"POST Requests With Details")
        end

        register_menu("Web/POST Requests",menu1, MENU_TOOLS_UNSORTED)


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
