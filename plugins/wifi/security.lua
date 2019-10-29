--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]


local gcs_type=Field.new("wlan.rsn.gcs.type")
local pcs_type=Field.new("wlan.rsn.pcs.type")
local pcs_count=Field.new("wlan.rsn.pcs.count")
local rsn_akms_type=Field.new("wlan.rsn.akms.type")
local rsn_akms_count=Field.new("wlan.rsn.akms.count")
local mcs_type=Field.new("wlan.wfa.ie.wpa.mcs.type")
local ucs_type=Field.new("wlan.wfa.ie.wpa.ucs.type")
local ucs_count=Field.new("wlan.wfa.ie.wpa.ucs.count")
local wpa_type=Field.new("wlan.wfa.ie.wpa.type")
local wpa_akms_type=Field.new("wlan.wfa.ie.wpa.akms.count")
local wpa_rsn_capabilites_mfpc=Field.new("wlan.rsn.capabilities.mfpc")
local wpa_rsn_capabilites_mfpr=Field.new("wlan.rsn.capabilities.mfpr")
local wlan_fixed_capabilites_privacy=Field.new("wlan.fixed.capabilities.privacy")
local wps_wifi_protected_setup_state=Field.new("wps.wifi_protected_setup_state")


function getString(str)
	if(str ~=nil and str()~=nil) then return tostring(str()) else return "NA" end 
end

local security={}

function security.getEncryption()
	local group_cipher=""
	local pairwise_cipher=""
	local key_managment=""
	local encryption_status=""
	local wpa_state=""
	local frame_protection=""

	-- RSN IE present
	-- Group cipher	
	if(getString(gcs_type)== "1")
		then
		group_cipher="WEP-40"
	elseif(getString(gcs_type)== "2") 
		then 
		group_cipher="TKIP"
	elseif(getString(gcs_type)== "4") 
		then 
		group_cipher="AES"
	elseif(getString(gcs_type)== "5")
		then
		group_cipher="WEP-104"
	end


	-- Pairwise cipher
	if(getString(pcs_type)=="1")
	 	then
		pairwise_cipher="WEP-40"
	elseif(getString(pcs_type)=="2")
		then
		if(getString(pcs_count)=="1")
			then
			pairwise_cipher="TKIP"
		elseif(getString(pcs_count)=="2")
			then
			pairwise_cipher="TKIP/AES"
		end
	elseif(getString(pcs_type)=="4")
		then
		if(getString(pcs_count)=="1")
			then
			pairwise_cipher="AES"
		elseif(getString(pcs_count)=="2")
			then
			pairwise_cipher="TKIP/AES"
		end
	elseif (getString(pcs_type)=="5")
		then
		pairwise_cipher="WEP-104"
	end

	-- Key management
	if(getString(rsn_akms_type)=="1")
		then
		if(getString(rsn_akms_count)=="1")
			then
			key_managment="802.1X"
		elseif(getString(rsn_akms_count)=="2")
			then
			key_managment="FT-over-802.1X"
		end
	elseif(getString(rsn_akms_type)=="2")
		then
		key_managment="PSK"
	elseif(getString(rsn_akms_type)=="3")
		then
		key_managment="FT-over-802.1X"
	elseif(getString(rsn_akms_type)=="6")
		then
		key_managment="PSK(SHA256)"
	end

	-- WPA vendor IE present
	-- Group cipher	

	if(getString(mcs_type)== "1")
		then
		group_cipher="WEP-40"
	elseif(getString(mcs_type)== "2") 
		then 
		group_cipher="TKIP"
	elseif(getString(mcs_type)== "4") 
		then 
		group_cipher="AES"
	elseif(getString(mcs_type)== "5")
		then
		group_cipher="WEP-104"
	end

	-- Pairwise Cipher
		if(getString(ucs_type)=="1")
	 	then
		pairwise_cipher="802.1X"
	elseif(getString(ucs_type)=="2")
		then
		if(getString(ucs_count)=="1")
			then
			pairwise_cipher="TKIP"
		elseif(getString(ucs_count)=="2")
			then
			pairwise_cipher="TKIP/AES"
		end
	elseif(getString(ucs_type)=="4")
		then
		if(getString(ucs_count)=="1")
			then
			pairwise_cipher="AES"
		elseif(getString(ucs_count)=="2")
			then
			pairwise_cipher="TKIP/AES"
		end
	elseif (getString(ucs_type)=="5")
		then
		pairwise_cipher="WEP-104"
	end

	-- Key management
	if(getString(wpa_type)=="1")
		then
		if(getString(wpa_akms_count)=="1")
			then
			key_managment="802.1X"
		elseif(getString(wpa_akms_count)=="2")
			then
			key_managment="FT-over-802.1X"
		end
	elseif(getString(wpa_type)=="2")
		then
		key_managment="PSK"
	elseif(getString(wpa_type)=="3")
		then
		key_managment="FT-over-802.1X"
	end

	-- Filling Encryption Status

	if(pairwise_cipher~="")
		then
		if(pairwise_cipher=="TKIP")
			then
			encryption_status="WPA"
		elseif(pairwise_cipher=="AES")
			then
			encryption_status="WPA2"
		elseif(pairwise_cipher=="TKIP/AES")
			then
			encryption_status="WPA/WPA2"
		elseif(pairwise_cipher=="WEP-104" or pairwise_cipher=="WEP-40")
			then
			encryption_status="WEP"
		end
	end

	-- WPS
	if(key_managment~="")
		then
		if(key_managment=="802.1X")
			then
			encryption_status=encryption_status.." ".."Enterprise"
		elseif(key_managment=="FT-over-802.1X")
			then
			encryption_status=encryption_status.." ".."Enterprise (802.11r support)"
		elseif(key_managment=="PSK")
			then
			encryption_status=encryption_status.." ".."Personal"
		end
	end


	if(getString(wps_wifi_protected_setup_state)=="0x00000002")
		then
		wpa_state="Enabled"
	elseif(getString(wps_wifi_protected_setup_state)~="NA")
		then
		wpa_state="Disabled"
	end

	-- 802.11w
	if(getString(wpa_rsn_capabilites_mfpc)=="1")
		then
		frame_protection="Mandatory"
	elseif(getString(wpa_rsn_capabilites_mfpc)~="NA" and getString(wpa_rsn_capabilites_mfpr)=="1")
		then
		frame_protection="Optional"
	else 
		frame_protection="NOT Applicable"
	end

	-- WEP
	if(gcs_type()==nil and mcs_type()==nil)
		then
		if(getString(wlan_fixed_capabilites_privacy)=="1")
			then
			pairwise_cipher="WEP"
			group_cipher="WEP"
			encryption_status="WEP"
		else
			pairwise_cipher="OPEN"
			group_cipher="OPEN"
			encryption_status="No-Encryption"
		end
	end

	return group_cipher,pairwise_cipher,key_managment,encryption_status,wpa_state,frame_protection
end

return security