const char www_style[] =
"<style>\n"
"body{\n"
"font-family:Arial,Helvetica,Verdana,Geneva,sans-serif;\n"
"background-color:#FFF;\n"
"font-size:13px;\n"
"}\n"
"table{font-size:16px;border:0px;empty-cells:show;border-spacing:0px;border-collapse:collapse;}\n"
"tr.hi{background-color:#EEE;}\n"
"tr.top{background-color:#CCC;}\n"
"td{padding:2px 10px;vertical-align:center;border:0px solid #D0D0D0;}\n"
"td.ex{color:#888888;font-size:13px;}\n"
".sml{font-size:12px;vertical-align:top;color:#444;}\n"
"hr{width:100%;height:3px;margin:0px;border:0px;background:#b90b67;}\n"

"a,input,button,.button{\n"
"background-color:#b90b67;\n"
"border:none;border-radius:6px;color:white;\n"
"padding:6px 16px;text-align:center;\n"
"text-decoration:none;\n"
"display:inline-block;\n"
"font-size:16px;\n"
"}\n"
/*
        "input,buttonBlue,.buttonBlue{\n"
        "background-color:#0000FF;\n"
        "border:none;border-radius:6px;color:white;\n"
        "padding:6px 16px;text-align:center;\n"
        "text-decoration:none;\n"
        "display:inline-block;\n"
        "font-size:16px;\n"
        "}\n"
*/
"input{background-color:#FFF;\n"
"border:none;border-radius:6px;\n"
"color:#000;padding:6px 16px;text-align:left;\n"
"}\n"
"a{vertical-align:middle;}\n"
"a:hover,button:hover{background-color:#d45398;}\n"
"div.up,div.upb,div.up0,div.up1{margin-left:10px;}\n"
"div.up{font-size:12px;}\n"
"div.upb{font-size:20px;}\n"
"div.up0{font-size:16px;color:#FF0000;}\n"
"div.up1{font-size:16px;color:#00C000;}\n"
"</style>\n"
;

const char www_script[] =
"<script>\n"
"var xmlHttp=new XMLHttpRequest();\n"
"var url='/getinfo.txt';\n"
"function niceTime(z){\n"
"var d=new Date(z * 1000);\n"
"return d.toLocaleString();\n"
"}\n"
"function handler (s){\n"
"var o=\"\";\n"
"var color=\"\";\n"
"var pid,ppid,lmver,licver;\n"
"var x=document.getElementById(\"xx\");\n"
"var d=new Date(0);\n"
"var myTime;\n"
"var algo,lock;\n"
"eval('var c='+ s);\n"
"if(c[\"status\"]!=\"0\"){\n"
"o+=\"<table><tr><td><font color=\\\"#ff0000\\\"><b>License Parsing Error:&nbsp;&nbsp;\"+c[\"status\"]+\n"
"\"&nbsp;&nbsp;\"+c[\"text\"]+\"</b></font></td></tr><table\";\n"
"} else {\n"
"lmver = parseInt(c[\"LMver\"]);\n"
"licver = parseInt(c[\"Licver\"]);\n"
"o+=\"<table width=\\\"100%\\\"><tr class=\\\"top\\\">\" +\n"
"\"<td>Vendor ID: <b>\"+c[\"VID\"]+\"</b></td>\"+\n"
"\"<td>LM Ver: \"+Math.floor(lmver/256)+\".\"+lmver%256+\"</td>\"+\n"
"\"<td>License Ver: \"+Math.floor(licver/256)+\".\"+licver%256+\"</td>\";\n"
"lock=c[\"HID\"];\n"
"if((lock)&&(lock.length>0)){\n"
"o+=\"<td><b>Node-locked</b></td>\";\n"
"} else {\n"
"o+=\"<td>not node-locked</td>\";\n"
"}\n"
"algo=c[\"AlgID\"];\n"
"switch (parseInt(algo)){\n"
"case 1: algo=\"RSA_2048_ADM_PKCS_V15\"; break;\n"
"case 2: algo=\"AES_128_OMAC\"; break;\n"
"case 3: algo=\"AES_256\"; break;\n"
"}\n"
"o+=\"</tr><tr class=\\\"hi\\\"><td colspan=\\\"4\\\">&nbsp;&nbsp;&nbsp;&nbsp;Algorithm ID: \"+\n"
"algo+\"</td></tr><tr class=\\\"hi\\\">\";\n"
"myTime=parseInt(c[\"time\"]);\n"
"o+=\"<td colspan=\\\"4\\\">&nbsp;&nbsp;&nbsp;&nbsp;Device Time: \"+myTime+\",&nbsp;&nbsp;<b>\"+\n"
"niceTime(myTime)+\"</b>&nbsp;&nbsp;<font size=\\\"-1\\\"><font color=\\\"AAAAAA\\\">\"+\n"
"\"(soft RTC initialized by browser's time)</font></font></td></tr>\";\n"
"pid=parseInt(c[\"PID\"]);\n"
"o+=\"<tr><td colspan=\\\"4\\\">&nbsp;</td></tr>\"+\n"
"\"<tr class=\\\"top\\\"><td colspan=\\\"4\\\">Product ID: \"+pid+'</td></tr>';\n"
"n=c[\"PPARTS\"].length;\n"
"for (i=0;i<n;i++){\n"
"ppid=parseInt(c[\"PPARTS\"][i][\"PPID\"]);\n"
"o+=\"<tr class=\\\"hi\\\"><td></td><td>Part \"+ppid+'</td>';\n"
"z=c[\"PPARTS\"][i][\"Perpetual\"];\n"
"if(z==1) o+=\"<td colspan=\\\"2\\\">Perpetual</td>\";\n"
"z=c[\"PPARTS\"][i][\"Start\"];\n"
"if(z){\n"
"color=\"#00C000\";\n"
"if(myTime<=parseInt(z)) color=\"#FF0000\";\n"
"o+=\"<td><font color=\\\"\"+color+\"\\\">Start: \"+z+\"<br>\"+niceTime(parseInt(z))+'</font></td>';\n"
"}\n"
"z=c[\"PPARTS\"][i][\"End\"];\n"
"if(z){\n"
"if(myTime>=parseInt(z)){\n"
"color=\"#FF0000\";\n"
"rem=0;\n"
"} else {\n"
"color=\"#00C000\";\n"
"rem=parseInt(z)-myTime;\n"
"}\n"
"o+=\"<td><font color=\\\"\"+color+\"\\\">End: \"+z+\"<br>\"+niceTime(parseInt(z))+'</font>';\n"
"if(rem>0) o+='<br>Remaining: '+rem+ \" sec.\";\n"
"o+='</td>';\n"
"}\n"
"o+=\"</tr>\";\n"
"f=c[\"PPARTS\"][i][\"FID\"];\n"
"fa=f.split(\",\");\n"
"o+=\"<tr><td colspan=\\\"2\\\"></td><td colspan=\\\"2\\\">\"\n"
"for (j=0;j<fa.length;j++){\n"
"f=parseInt(fa[j]);\n"
"if(!isNaN(f))\n"
"o+=\"Feature \"+f+\"<br>\";\n"
"}\n"
"o+=\"</td></tr>\";\n"
"if(i<n-1) o+=\"<tr><td colspan=\\\"4\\\">&nbsp;</td></tr>\";\n"
"}\n"
"o+=\"<tr><td colspan=\\\"4\\\">&nbsp;</td></tr>\";\n"
"o+=\"<tr class=\\\"hi\\\"><td colspan=\\\"2\\\">fit_licenf_validate_license():</td><td colspan=\\\"2\\\">\";\n"
"if(c[\"validate\"]==\"0\") o+=\"<font color=\\\"#00C000\\\">\"; else o+=\"<font color=\\\"#FF0000\\\">\";\n"
"o+=\"<b>\"+c[\"validate\"] + \"&nbsp;&nbsp;\" + c[\"vtext\"] + \"</b></font></td></tr>\";\n"
"/*  o+=\"<tr><td colspan=\\\"4\\\">&nbsp;</td></tr>\"; */\n"
"o+=\"</table>\";\n"
"}\n"
"x.innerHTML=o;\n"
"if(myTime<1000000)\n"
"setTimeout(\"settime()\",100);\n"
"else\n"
"setTimeout(\"getinfo()\",1000);\n"
"}\n"
"function getinfo(){\n"
"if(xmlHttp){\n"
"xmlHttp.open('GET',url,true);\n"
"xmlHttp.onreadystatechange=function (){\n"
"if(xmlHttp.readyState==4){\n"
"handler(xmlHttp.responseText);\n"
"}\n"
"};\n"
"xmlHttp.send(null);\n"
"}\n"
"}\n"
"function sethandler(){\n"
"setTimeout(\"getinfo()\",100);\n"
"}\n"
"function settime(){\n"
"var d=new Date();\n"
"var n=Math.floor(d.getTime()/1000);\n"
"var url=\"/set?unixtime=\"+n;\n"
"var x=document.getElementById(\"xx\");\n"
"if(x) x.innerHTML=\"Setting Time ...\";\n"
"if(xmlHttp){\n"
"xmlHttp.open('GET',url,true);\n"
"xmlHttp.onreadystatechange=function (){\n"
"if(xmlHttp.readyState==4){\n"
"sethandler();\n"
"}\n"
"};\n"
"xmlHttp.send(null);\n"
"}\n"
"}\n"
"function isEmpty(id){\n"
"if(!document.getElementById(id).value){\n"
"return confirm(\"You did not select a file to upload.\\n\\n\"+\n"
"\"Uploading an empty item will remove the V2C/key from the device's EEPROM storage.\\n\\n\"+\n"
"\"Click [ OK ] to upload an empty item\\n\"+\n"
"\"Click [ Cancel ] to go back to file selection\");\n"
"}\n"
"return true;\n"
"}\n"
"</script>\n"
;

const char www_form[] =
"<table width=\"100%\">\n"
		"<form action=\"/led1toggle\" method=\"get\">\n"
		"<tr height=\"54px\">\n"
		"<td>&nbsp;</td>\n"
		"<td><button type=\"submit\">Toggle Green</button></td>\n" // LED1
		"</form>\n"
		"<form action=\"/led2toggle\" method=\"get\">\n"
//		"<td><buttonBlue type=\"submit\">Toggle Blue</button></td>\n" // LED2
        "<td><button type=\"submit\">Toggle Blue</button></td>\n" // LED2
		"</tr>\n"
		"</form>\n"
"<form action=\"/consume\" method=\"get\">\n"
"<tr class=\"top\"><td colspan=\"3\">fit_licenf_consume_license():</td></tr>\n"
"<tr height=\"54px\">\n"
"<td>&nbsp;</td>\n"
"<td>Feature ID: <input name=\"featureid\" type=\"number\" min=\"0\" max=\"4294967295\" size=\"10\" value=\"1\"></td>\n"
"<td><button type=\"submit\">Submit</button>&nbsp;&nbsp;&nbsp;</td>\n"
"</tr>\n"
"</form>\n"
"<form action=\"/v2c\" method=\"post\" enctype=\"multipart/form-data\" onsubmit=\"javascript:return isEmpty('fv2c')\">\n"
"<tr class=\"top\">\n"
"<td>License (V2C):</td>\n"
"<td colspan=\"2\" id=\"v2c\" class=\"ex\"></td>\n"
"</tr>\n"
"<tr height=\"54px\">\n"
"<td></td>\n"
"<td><input id=\"fv2c\" name=\"Datei\" type=\"file\" size=\"50\" accept=\".v2c\"></td>\n"
"<td><button type=\"submit\">Upload&nbsp;File</button>&nbsp;&nbsp;&nbsp;</td>\n"
"</tr>\n"
"</form>\n"
"<form action=\"/rsakey\" method=\"post\" enctype=\"multipart/form-data\" onsubmit=\"javascript:return isEmpty('frsa')\">\n"
"<tr class=\"top\">\n"
"<td>RSA&nbsp;Public&nbsp;Key:</td>\n"
"<td colspan=\"2\" id=\"rsa\" class=\"ex\"></td>\n"
"</tr>\n"
"<tr height=\"54px\">\n"
"<td></td>\n"
"<td><input id=\"frsa\" name=\"Datei\" type=\"file\" size=\"50\" accept=\".bin,.pem\"></td>\n"
"<td><button type=\"submit\">Upload&nbsp;File</button>&nbsp;&nbsp;&nbsp;</td>\n"
"</tr>\n"
"</form>\n"
"<form action=\"/aeskey\" method=\"post\" enctype=\"multipart/form-data\" onsubmit=\"javascript:return isEmpty('faes')\">\n"
"<tr class=\"top\">\n"
"<td>AES Key:</td>\n"
"<td colspan=\"2\" id=\"aes\" class=\"ex\"></td></tr>\n"
"</tr>\n"
"<tr height=\"54px\">\n"
"<td></td>\n"
"<td><input id=\"faes\" name=\"Datei\" type=\"file\" size=\"50\" accept=\".bin\"></td>\n"
"<td><button type=\"submit\">Upload&nbsp;File</button>&nbsp;&nbsp;&nbsp;</td>\n"
"</tr>\n"
"</form>\n"
"</table>\n"
;
