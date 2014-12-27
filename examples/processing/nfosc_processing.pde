/**
 * nfosc processing demo by Martin Kaltenrunner
 * http://code.google.com/p/nfosc/
 */
 
import oscP5.*;
import netP5.*;

OscP5 oscP5;
NetAddress myRemoteLocation;

void setup() {
  size(100,100);
  frameRate(25);
  /* listening for incoming OSC messages at port 3333 */
  oscP5 = new OscP5(this,3333);
}


void draw() {
  background(0);  
}

/* incoming OSC messages are forwarded to the oscEvent method. */
void oscEvent(OscMessage theOscMessage) {
 if (theOscMessage.addrPattern().equals("/nfosc/add")) {
   tagAdded(theOscMessage.get(0).intValue(),theOscMessage.get(1).intValue(),theOscMessage.get(2).intValue(),theOscMessage.get(3).stringValue());
 } else if (theOscMessage.addrPattern().equals("/nfosc/del")) {
     tagRemoved(theOscMessage.get(0).intValue(),theOscMessage.get(1).intValue(),theOscMessage.get(2).intValue(),theOscMessage.get(3).stringValue());   
 }
}

void tagAdded (int devID,int tagID,int tagType,String uID) {
  println("add tag #"+tagID+" on device #"+devID);
}

void tagRemoved (int devID,int tagID,int tagType,String uID) {
  println("del tag #"+tagID+" on device #"+devID);
}
