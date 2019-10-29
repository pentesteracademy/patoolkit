--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]


do
  if not gui_enabled() then return end

        local util=require('util')
        local frame_number=Field.new("frame.number")
        local http_request=Field.new("http.request")
        local host=Field.new("http.host")
        local request_uri=Field.new("http.request.uri")
        local user_agent=Field.new("http.user_agent")
        local is_file=Field.new("http.file_data")
        local resp_code=Field.new("http.response.code")
        local request_in=Field.new("http.request_in")
        local content_length=Field.new("http.content_length")
        local content_type=Field.new("http.content_type")
        local container= {}
        local requests={}

        function getRequest()
          if(http_request()==nil) then return false else return true end
        end

        function getFile()
          if(resp_code()==nil) then return false else return true end
        end

        local function getString(str)
          if(str~=nil) then return tostring(str) else return "NA" end
        end

        function getFrame()
            return getString(frame_number())
        end

local function init_listener()

    local tap = Listener.new("frame", "http")

    -- Called at the end of live capture run
    function tap.reset()
      container= {}
      requests={}
    end

    -- Called once each time the filter of the tap matches
    function tap.packet(pinfo, tvb)

        -- check if its a request, if it is store host, useragent and the path of the request
        if getRequest()
          then
            local uri=getString(request_uri())
            local file={}
            file["host"]=getString(host())
            file["user_agent"]=getString(user_agent())
            file["path"]=uri
            requests[getFrame()]=file

        -- check for response code 200 ok and whether the is a request in field inside the response, save the content
        -- length, content type of the file in the response, map it with the request to which it corresponds and store it in container table
        elseif (getFile() and request_in() and getString(resp_code())=="200")
          then
            local req=requests[getString(request_in())]
            local file={}
            file["host"]=req["host"]
            file["user_agent"]=req["user_agent"]
            file["path"]=req["path"]
            file["content_type"]=getString(content_type())
            file["content_length"]=getString(content_length())
            table.insert(container,file)
        end
    end
end

        local function get_request(win,stringToFind)
            local header=  " __________________________________________________________________________________________________________________________________\n"
                         .."|   S.no   |       Host       |       User Agent       |              Path              |       Content Type      | Content Length |\n"



           
            win:set(header)
            local count=0
            for k,v in ipairs(container)do           -- <- table whoes data you want print

            if(util.searchStr({v["host"],v["user_agent"],v["path"],v["content_type"],v["content_length"]},stringToFind))
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
                    ["value"]=v["content_type"],
                    ["length"]=25,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=v["content_length"],
                    ["length"]=16,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=false
                  }                                    
                }
                  win:append("|----------------------------------------------------------------------------------------------------------------------------------|\n")  
                  
                  win:append(acf(acf_settings,"|"))  
                end
          end
          win:append("|__________________________________________________________________________________________________________________________________|\n")     

        end 


        function menu1()
            util.dialog_menu(get_request,"Downloaded Files")
        end

        register_menu("Web/Downloaded Files",menu1, MENU_TOOLS_UNSORTED)



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
