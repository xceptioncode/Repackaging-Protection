package=$(aapt dump badging "$*" | awk '/package/{gsub("name=|'"'"'","");  print $2}')
#activity=$(aapt dump badging "$*" | awk '/activity/{gsub("name=|'"'"'","");  print $2}')
#echo "$package"
pid=$(adb shell pidof "$package")
echo "$pid"
