package=$(aapt dump badging "$*" | awk '/package/{gsub("name=|'"'"'","");  print $2}')
#activity=$(aapt dump badging "$*" | awk '/activity/{gsub("name=|'"'"'","");  print $2}')
#echo "$package"
meminfo=$(adb shell dumpsys meminfo "$package")
echo "$meminfo"
