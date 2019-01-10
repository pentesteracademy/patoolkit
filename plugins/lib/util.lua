--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]


local util={}


-- this function will work for single stage strings, if there are recursive objects this function won't give proper outputs
function util.searchDuo(tbl, tbl2,val)

	local updated_table={}

	for k,v in ipairs(tbl)do

		for key,value in pairs(tbl2[v])do
			if(string.lower(v):find(string.lower(val))~=nil)
				then
				return true
			end
		end
	end
	return false
end
------------------------  Search Function by String --------------------------

-- the first parameter is a table of strings to match

function util.searchStr(tbl,val)
	for k,v in ipairs(tbl)do
		if(string.lower(v):find(string.lower(val))~=nil)
			then
			return true
		end
	end
	return false
end

----------------------------------- String Function for table with 
function util.searchTable(tbl,val)
	for k,v in pairs(tbl)do

		if(string.lower(v):find(string.lower(val))~=nil)
			then
			return true
		end
	end
	return false
end



-- dialog menu function encorperating search
function util.dialog_menu(function_name,window_name)
    
  local win = TextWindow.new(window_name);
  
        -- printing out the table for first time
  function_name(win,"")

  -- function to be called when search button is clicked
  local function search()

      -- function to be called when ok button is clicked in new dailog box
      local function input(find)

        -- call the print daat function with string to find
        function_name(win,find)
      end

      -- defining new dailog box 
      new_dialog("Enter text to search",input, "Text")
  end      

  -- function to be called when reset button is clicked
  local function reset()
  	function_name(win,"")
  end
  -- adding reset and search button, reset button will call print_Data function with "" as parameter
  win:add_button("Reset",reset)
  win:add_button("Search",search)

end

return util