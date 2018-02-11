dim wsh, fso, cur_path, exe_path, conf_path, exe_string, reg_path, reg_name, reg_value
set wsh = wscript.createobject("wscript.shell")
set fso = createobject("Scripting.FileSystemObject")
cur_path = fso.GetFolder(".").Path
exe_path = cur_path + "\freesocks.exe"
conf_path = cur_path + "\freesocks.json"
exe_string = exe_path + " -c " + conf_path
reg_path = "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\"
reg_name = "AutoConfigURL"
reg_value= "file:///" + cur_path + "\gfwlist.pac"
wsh.regwrite (reg_path & reg_name), reg_value, "REG_SZ"
wsh.run exe_string, 1, true
wsh.regdelete(reg_path & reg_name)