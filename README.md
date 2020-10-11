# Outlook_Profile_Registry_Customizer
  
* Create an master e-mail profile
* Export "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Outlook" using regedit
* Remove backslash + newline from all values
* Create an config file like example-config.ini
* Encode config file as base64
* Call the exe with "modify reg-in-file reg-out-file config-file-as-base64" argument
* Import the new reg file
  
Customization of the signature is possible using the "signature src-folder config-file-as-base64" argument, use "##KEY##" from the "[newprofile]" area of the config file as placeholder in the source files.
  
Based on https://binary-butterfly.de/artikel/outlook-2016-profil-zu-neuem-nutzer-umziehen/