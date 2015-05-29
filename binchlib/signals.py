import blinker

focus = blinker.Signal()
set_prompt = blinker.Signal()
set_prompt_yn = blinker.Signal()
set_message = blinker.Signal()
redraw_status = blinker.Signal()
call_delay = blinker.Signal()
