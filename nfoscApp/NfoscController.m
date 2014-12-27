#import "NfoscController.h"
#import "nfosc.h"
#import <stdlib.h>

@implementation NfoscController

- (id) init {
	self = [super init];
	_running = false;
	
	return self;
}

- (void)applicationDidFinishLaunching:(NSApplication *)app
{
	if (!nfosc_check()) {
		[_hostname setEnabled:false];
		[_port setEnabled:false];
		[_info setStringValue:@"no device found"];
		[_button setEnabled:false];
	} else {
		[_hostname setEnabled:true];
		[_port setEnabled:true];
		[_info setStringValue:@"nfOSC is stopped"];
		[_button setEnabled:true];
	}
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)app
{
	[self stop:app];
	return YES;
}

- (void)applicationWillTerminate:(NSApplication *)app
{
	[self stop:app];
}

- (IBAction)start:(id)sender {
	[_info setStringValue:@"nfOSC is starting"];

    const char *hostname = [[_hostname stringValue] UTF8String];
	const char *port = [[_port stringValue] UTF8String];

    nfosc_set_hostname_and_port(hostname, port);
	nfosc_start();

    if (nfosc_running()) {
	
		[_hostname setEnabled:false];
		[_port setEnabled:false];
		[_info setStringValue:@"nfOSC is running"];
		[_button setTitle:@"Stop"];
		_running = true;
	} else {
		[_info setStringValue:@"nfOSC is stopped"];
	}

}

- (IBAction)stop:(id)sender {
	nfosc_stop();
	
	if (!nfosc_running()) {
		[_hostname setEnabled:true];
		[_port setEnabled:true];
		[_info setStringValue:@"nfOSC is stopped"];
		[_button setTitle:@"Start"];
	
		_running = false;
	}
}
	
- (IBAction)startstop:(id)sender {
	if (!_running) {
		[self start:sender];
	}
	else {
		[self stop:sender];
	}
}

- (IBAction)reset:(id)sender {

}

@end
