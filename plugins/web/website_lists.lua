--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]

do

  -- Table to store the list of both http and https urls.
  local output = {}
  local store={}
  -- If GUI is not enabled exit.
  if not gui_enabled() then return end

  local util=require('util')
  -- New field extractors.
  local hostname = Field.new("http.host")
  local method = Field.new("http.request.method")
  local src = Field.new("ip.src")
  local dst = Field.new("ip.dst")
  local dns_response =Field.new("dns.flags.response")
  local dns_typ =Field.new("dns.qry.type")
  local dns_name =Field.new("dns.qry.name")
  local dns_ipv4 =Field.new("dns.a")
  local dns_ipv6 =Field.new("dns.aaaa")
  local http=Field.new("http.request")
  local tls=Field.new("tls.handshake.client_point")
  local time=Field.new("frame.time_relative")

  local function getString(str)
    if(str~=nil) then return tostring(str) else return "NA" end
  end

  function dns()
    if(getString(dns_response())=='1' )
      then
      return true
    else
      return false
    end

  end
  function dns_type()
    if(dns_typ()~=nil and (getString(dns_typ())=='1' or getString(dns_typ())=='28') and (dns_ipv4()~=nil or dns_ipv6()~=nil))
      then
      return true
    else
      return false
    end

  end
  local function init_listener()

    local tap = Listener.new("frame", "(dns || ((tls.handshake.client_point || http.request) && tcp)) && ip")

    -- Called at the end of live capture run
    function tap.reset()
      output = {}
      store={}
    end

    -- Called at the end of the capture to print the summary
    function tap.draw()

    end

    -- Called once each time the filter of the tap matches
    function tap.packet(pinfo, tvb)
      
      -- Extracts ip from the listener.

      if(dns~=nil and dns() and dns_type())
        then
        local str=""
        if(dns_ipv4()~=nil)
          then
              str=getString(dns_ipv4())
              if(store[str]==nil)
                then
                store[str]=getString(dns_name())
              end
        end

        if(dns_ipv6()~=nil)
          then
              str=getString(dns_ipv6())
              if(store[str]==nil)
                then
                store[str]=getString(dns_name())
              end
        end
    elseif(http()~=nil or tls()~=nil)
      then
        local ip = getString(src())
        local data_exchanged = tonumber(tvb:len())
        local dest=getString(dst())
        if not output[ip] then
          output[ip] = {}
        end
        local ishttp=0
        local isconnect=0
        local url =""
        if(http()~=nil)
          then
            url = getString(hostname())
            if getString(method()) == "CONNECT" then
                ishttp = 1
                isconnect=1
            end
            if(store[dest]==nil)
              then
              store[dest]=url
            end
        else
          url=dest
          ishttp=1
        end

        -- Creates a table with key as ip (src_ip) if its doesn't exist 


        -- Initialises a table with multiple keys for unique URL
            if not output[ip][url] then
              output[ip][url] = {
                ["ip"]=dest,
                ["data_exchanged"] = data_exchanged, -- 
                ["packet_count"] = 1, -- Counts total packet exchange
                ["https"] = ishttp, -- Initially non-HTTPS
                ["connect"]=isconnect,
                ["time"]=tonumber(tostring(time() or "0"))
              }
            else
              output[ip][url]["packet_count"] = output[ip][url]["packet_count"] + 1
              output[ip][url]["data_exchanged"] = output[ip][url]["data_exchanged"] + data_exchanged
             output[ip][url]["time"] =tonumber(tostring(time() or "0"))
            end
        

        -- The CONNECT method can be used to access websites that use SSL (HTTPS).
        

      

      end
    end
  end

  -- Displays output in a better format.
  local function prettify_display(win,output, is_https,stringToFind)
    local col_serial_len=12
    local column_1_length=32
    local column_2_length=16
    local column_3_length=24
    local column_4_length=20
    local column_5_length=16
    local column_6_length=12

    
    -- Prints a pretty output of the data analysed so far
    win:set("")
    for ip, val in pairs(output) do
      win:append("Client: ".. ip.."\n")
      win:append(" __________________________________________________________________________________________________________________________________________\n")
      win:append("|    S.NO    |              Domain            |   IP address   |    Packets exchanged   |   Data exchanged   |  %age packets  |  Duration  |\n")
      local count=0
      for url, tbl in pairs(val) do
        
        if(tbl["https"]==1 and tbl["connect"]==0)
          then
          if(store[url]~=nil)
            then
            url=store[url]
          else
            url="NA"
          end
        end
        if tbl["https"] == is_https then
           if(util.searchStr({url,tbl["ip"],tostring(tbl["packet_count"]),tostring(tbl["data_exchanged"]),tostring((tbl["packet_count"]/tbl["data_exchanged"])*100),tostring(tbl["time"])},stringToFind))
                then
                count=count+1
          win:append("|------------------------------------------------------------------------------------------------------------------------------------------|\n")
          win:append("")
          local global={tostring(count),false}
          local global1={url,false}
          win:append("|"..format_str(global[1],col_serial_len,global,"").."|"..format_str(global1[1],column_1_length,global1,",").."|"..format_str(tbl["ip"],column_2_length,global,",").."|"..format_str(tostring(tbl["packet_count"]),column_3_length,global," ").."|"..format_str(tostring(tbl["data_exchanged"]),column_4_length,global," ").."|"..format_str(tostring((tbl["packet_count"]/tbl["data_exchanged"])*100),column_5_length,global," ").."|"..format_str(tostring(tbl["time"]),column_6_length,global," ").."|\n")
    

          while(global1[2]) do
              win:append("|"..format_str("",col_serial_len,global," "))
            if(global1[2])
              then
              global1[2]=false
              win:append("|"..format_str(global1[1],column_1_length,global1," "))
            else
              win:append("|".. format_str("",column_1_length,global1," "))
            end
              win:append("|".. format_str("",column_2_length,global,","))
              win:append("|".. format_str("",column_3_length,global,","))
              win:append("|".. format_str("",column_4_length,global,","))
              win:append("|".. format_str("",column_5_length,global,","))
              win:append("|".. format_str("",column_6_length,global," ").."|\n")
          end
        end
      end
    end
         win:append("|__________________________________________________________________________________________________________________________________________|\n\n")
    end

 

  end

  -- Displays list of HTTPS urls in the GUI.
  local function dialog_menu2(win,str)

    prettify_display(win,output, 1,str)

  end

  -- Displays list of HTTP urls in the GUI.
  local function dialog_menu1(win,str)

    prettify_display(win,output, 0,str)

  end

  function menu1()
      util.dialog_menu(dialog_menu1,"List of urls")
  end
  function menu2()
    util.dialog_menu(dialog_menu2,"List of urls")
end
  


  register_menu("Web/Websites visited over HTTP",menu1, MENU_TOOLS_UNSORTED)
  register_menu("Web/Websites visited over HTTPS",menu2, MENU_TOOLS_UNSORTED)

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