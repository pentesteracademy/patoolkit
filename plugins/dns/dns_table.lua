--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]


do
  if not gui_enabled() then return end

        local util=require('util')
        local frame_number=Field.new("frame.number")
        local dns_resp_type=Field.new("dns.resp.type")
        local dns_resp_name=Field.new("dns.resp.name")
        local dns_answer=Field.new("dns.a")
        local container={}
        local container_store={}

        local function getString(str)
          if(str()~=nil) then return tostring(str()) else return "NA" end
        end

local function init_listener()

    local tap = Listener.new("frame", "dns.flags.response == 1")

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
      local type={dns_resp_type()}
      local name={dns_resp_name()}
      local answer={dns_answer()}
      local count=0
      for k,v in ipairs(type)
        do
          if(getString(v)=="1")
            then
                count=count+1
                local rec={}

                if (name[k]~=nil and answer[count] ~=nil)
                	then
	                rec["domain"]=getString(name[k])
	                rec["ip"]=getString(answer[count])
	                if container_store[rec["domain"].."-"..rec["ip"]] == nil
	                	then
	                	container_store[rec["domain"].."-"..rec["ip"]]=true
	                	table.insert(container,rec)
	                end
            end
          end
      end
    end
end

    
        local function get_dns(win,stringToFind)
            local header=  " ______________________________________________________\n"
                         .."|   S.no   |     Domain Name    |       IP Address     |\n"
            win:set(header)
            local count=0
            for k,v in pairs(container)do           -- <- table whoes data you want print

            if(util.searchStr({v["domain"],v["ip"]},stringToFind))
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
                    ["value"]=v["domain"],
                    ["length"]=20,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=false
                  },
                  { 
                    ["value"]=v["ip"],
                    ["length"]=22,
                    ["delimiter"]=",",
                    ["next"]=true,
                    ["branch"]=false
                  }                                 
                }
                  win:append("|------------------------------------------------------|\n")  
                  
                  win:append(acf(acf_settings,"|"))  
                end
          end
          win:append("|______________________________________________________|\n")     

        end 

        function menu1()
            util.dialog_menu(get_dns,"Domain Name Resolutions")
        end
        register_menu("DNS/Resolution",menu1, MENU_TOOLS_UNSORTED)

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
