.. image:: https://user-images.githubusercontent.com/743886/43845704-6dbd2558-9ae1-11e8-9f77-239210fe7b6a.png

#########################################################################
PA Toolkit (Pentester Academy Wireshark Toolkit)
#########################################################################

This branch is created for installing PA Toolkit in Wireshark Global plugins directory on Linux based operating systems.

############
Installation
############

Steps:

1. Copy the folders present in "plugins" directory to Wireshark **Global plugins** directory.  

    One can get the location of wireshark plugins directory by checking *Help > About Wireshark > Folders*

2. Set LUA_PATH Enviornment variable.

    Add absolute path of "lib" folder present in wireshark global plugins directory to LUA_PATH variable. This can be done by one of the following methods:

    **Method 1 (Preferred)**
    
    Create a shell script file in "/etc/profile.d" directory with the following content:
 
        export LUA_PATH="$LUA_PATH;/usr/lib/x86_64-linux-gnu/wireshark/plugins/2.6/lib/?.lua"

    *Note:* The filename should end with ".sh"

    **Method 2:** 

    Add LUA_PATH variable in "/etc/enviornment". If LUA_PATH variable has not been defined in "/etc/enviornment" file, append the following line in "/etc/enviornment" file.

        LUA_PATH="/usr/lib/x86_64-linux-gnu/wireshark/plugins/2.6/lib/?.lua"

    If LUA_PATH variable already exists, then append the path seperated by ";" to LUA_PATH variable. For e.g

       LUA_PATH="/?.lua;/usr/lib/x86_64-linux-gnu/wireshark/plugins/2.6/lib/?.lua"

    where "/?.lua" is existing value of LUA_PATH variable.

    *Note:* Please use Wireshark global plugin folder path of your machine instead of the path mentioned in the above methods.


3. Start wireshark. :) 


#############
Terms of Use
#############

- This is licensed under GPL just as Wireshark.

########
License
########

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License v2 as published by
the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
