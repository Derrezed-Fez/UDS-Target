/*
  Gateway
*/
void handle_vcds_101(int can, struct canfd_frame frame) {
  if(verbose) plog("Received VCDS 0x101 gateway request\n");
  char resp[150];
  if(frame.data[0] == 0x30) { // Flow control
    flow_control_push_to(can,0x102);
    return;
  }
  switch(frame.data[1]) {
    //Pkt: 710#02 10 03 55 55 55 55 55 
    case 0x10: // Diagnostic Session Control
      frame.can_id = 0x102;
      frame.len = 8;
      frame.data[0] = 0x06;
      frame.data[1] = 0x50;
      frame.data[2] = 0x03;
      frame.data[3] = 0x00;
      frame.data[4] = 0x32;
      frame.data[5] = 0x01;
      frame.data[6] = 0xF4;
      frame.data[7] = 0xAA;
      write(can, &frame, CAN_MTU);
      break;
    case 0x11: // ECU Reset
    	plog("Recevice ECU Reset\n");
    	if(!strcmp(cfg_getstr(cfg, "ECU_RESET"), "false" )) {
    		//sending positive response for $11
			frame.can_id = 0x102;
			frame.len = 2;
			frame.data[0] = 0x51;
			frame.data[1] = frame.data[2];
			frame.data[2] = 0x00;
			frame.data[3] = 0x00;
			frame.data[4] = 0x00;
			frame.data[5] = 0x00;
			frame.data[6] = 0x00;
			frame.data[7] = 0x00;
			write(can, &frame, CAN_MTU);
    	} else {
		//sending request pending response for $11, and then become unresponsive for some time
          frame.can_id = 0x102;
          frame.len = 8;
          frame.data[0] = 0x03;
          frame.data[1] = 0x7F;
          frame.data[2] = 0x11;
          frame.data[3] = 0x78;
          frame.data[4] = 0xFF;
          frame.data[5] = 0xFF;
          frame.data[6] = 0xFF;
          frame.data[7] = 0xFF;
          write(can, &frame, CAN_MTU);
          int sleep_time = cfg_getint(cfg, "ECU_RESET_DOS_TIME");
          plog("Server going to sleep for %02X seconds. ECU_RESET Vuln.", sleep_time);
          sleep(sleep_time);
    	}
          break;
    case 0x22: // Read Data By Identifier
      if(frame.data[2] == 0xF1) {
        switch(frame.data[3]) {
        // WARNING: WILL ACTIVATE THE FINAL FLAG, DO NOT SWITCH ON UNLESS YOU WANT TO BE AN 31337 H4X0R
        case 0xFF:
          if(false){