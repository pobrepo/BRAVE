var hubitatIP = "192.168.1.200:8080";
var accessToken = "ab1c91a0-1e3b-4eea-83fd-2c04923eaf67";

var b1="7c:c6:b6:72:11:88", b2="7c:c6:b6:64:8f:b5";
var s1="7c:c6:b6:9e:8f:7d", s2="7c:c6:b6:91:cf:3f", s3="7c:c6:b6:9e:7c:09";

var garIds = [204,205,206];
var actToDoor = {"single":0,"double":1,"triple":2};

var lastBtnCnt={}, lastState1=null, lastS1Cnt=null, lastState2=null, lastS2Cnt=null, lastState3=null, lastS3Cnt=null;

function buildUrl(id, action){
  return "http://" + hubitatIP + "/apps/api/80/devices/" + id + (action?"/"+action:"") + "?access_token=" + accessToken;
}

function ts(){ var now=new Date(); var cdt=new Date(now.getTime()-(5*60*60*1000)); return cdt.toISOString().slice(0,19).replace('T',' '); }
function log(m){ print(ts()+" "+m); }

function hexbuf(buf){var h="";for(var i=0;i<buf.length;i++){var x=buf.at(i).toString(16);if(x.length<2)x="0"+x;h+=x;}return h;}
function cntOf(raw){return raw&&raw.length>=6?raw.slice(4,6):"NA";}
function isNewer(p,n){if(p==null)return true;var P=parseInt(p,16),N=parseInt(n,16);var d=(N-P+256)%256;return d>0&&d<128;}
function decodeAction(raw){
  if(!raw) return {act:"none", why:"no data"};
  for (var i=0; i<=raw.length-4; i+=2){
    if (raw.slice(i,i+2)==="3a"){
      var code = raw.slice(i+2,i+4);
      if (code==="01") return {act:"single", at:i};
      if (code==="02") return {act:"double", at:i};
      if (code==="03") return {act:"triple", at:i};
      if (code==="04") return {act:"long",   at:i};
      return {act:"none", why:"3a without valid code"};
    }
  }
  return {act:"none", why:"no 3aXX marker"};
}

if(!(res.service_data&&res.service_data.fcd2)) return;
var rawB=hexbuf(res.service_data.fcd2), cntB=cntOf(rawB);
if(mac===b1||mac===b2){
  var name=(mac===b1)?"BUTTON 1":"BUTTON 2";
  var dec=decodeAction(rawB);
  if(dec.act==="none"){
    log(name+": unknown action ("+dec.why+") mac="+mac+" cnt="+cntB+" rssi="+(res.rssi||"NA")+" raw="+rawB+" DROP");
    return;
  }
  log(name+": "+dec.act+" mac="+mac+" cnt="+cntB+" rssi="+(res.rssi||"NA"));
  controlDoors(mac, dec.act, cntB, res.rssi||"NA", rawB);
}

function controlDoors(mac, command){
  var idx = actToDoor[command];
  if(idx == null || idx < 0 || idx >= garIds.length) return;

  var garId = garIds[idx];
  var url = buildUrl(garId, "bleAction/open");
  Shelly.call("http.get", {url:url}, function(res){});
  log("BLE EVENT: door="+(idx+1)+" action=open gar="+garId);
}

function doorIndexForMac(mac){
  if(mac===s1) return 1;
  if(mac===s2) return 2;
  if(mac===s3) return 3;
  return 0; // unknown
}

function handleSensorEvent(mac, rawS, cntS, rssi){
  var state = rawS.slice(20,22)==="01" ? "open" : "closed";
  var garDeviceId = 0;
  var lastState = null;

  if(mac===s1){ garDeviceId=204; lastState=lastState1; }
  else if(mac===s2){ garDeviceId=205; lastState=lastState2; }
  else if(mac===s3){ garDeviceId=206; lastState=lastState3; }

  if(garDeviceId>0){
    if(state!==lastState){
      var idx = doorIndexForMac(mac);
      log("SENSOR " + idx + ": state=" + state + " mac=" + mac + " cnt=" + cntS + " rssi=" + rssi);
      var url = buildUrl(garDeviceId, "syncState/"+state);
      Shelly.call("http.get", {url:url}, function(res){
        if(res && res.code!==200){ log("SYNC FAILED: "+(res.code||"null")); }
        else { log("SYNC SUCCESS: "+state); }
      });

      if(mac===s1) lastState1=state;
      else if(mac===s2) lastState2=state;
      else if(mac===s3) lastState3=state;
    }
  }
}

BLE.Scanner.Start({duration_ms:BLE.Scanner.INFINITE_SCAN,active:true});
BLE.Scanner.Subscribe(function(ev,res){
  if(ev!==BLE.Scanner.SCAN_RESULT || !res || !res.addr) return;
  var mac = res.addr.toLowerCase();

  if(mac===s1||mac===s2||mac===s3){
    if(!(res.service_data&&res.service_data.fcd2)) return;
    var rawS = hexbuf(res.service_data.fcd2);
    var cntS = cntOf(rawS);
    handleSensorEvent(mac, rawS, cntS, res.rssi||"NA");
    return;
  }

  if(!(res.service_data&&res.service_data.fcd2)) return;
  var rawB = hexbuf(res.service_data.fcd2);
  var cntB = cntOf(rawB);

  if(mac===b1||mac===b2){
    var name = (mac===b1) ? "BUTTON 1" : "BUTTON 2";
    var dec = decodeAction(rawB);
    if(dec.act==="none"){
      log(name+": unknown action ("+dec.why+") mac="+mac+" cnt="+cntB+" rssi="+(res.rssi||"NA")+" raw="+rawB+" DROP");
      return;
    }
    log(name+": "+dec.act+" mac="+mac+" cnt="+cntB+" rssi="+(res.rssi||"NA"));
    controlDoors(mac, dec.act, cntB, res.rssi||"NA", rawB);
  }
});