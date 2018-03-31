# airspy_tcp
## a rtl-tcp compatible, IQ server for airspy SDR

airspy_tcp is a direct port of [rtl_tcp](https://github.com/osmocom/rtl-sdr) for the [airspy](https://airspy.com/).

As the rtl_tcp protocol is only 8 bits IQ, man will loose the major advantage of an airspy : its 12bits DAC, but :

1. It will works with any rtl_tcp capable frontend (Well I hope, see below)
2. As it's opensource, you could compile on any Linux (and perhaps other UNIXes) server

Notes :
 - I try it with gqrx and sdrangelove frontend only. Other tests are welcome.
 - The rtl_tcp frontend client must set one of the only two sample frequencies that the airspy supports. Others sample frequencies are not supported.
 - It must work with airspy mini too, but not tested.
