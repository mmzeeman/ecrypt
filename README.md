# ecrypt

Experimental proof of concept crypto nif using OpenSSL's engine api.

Erlangs current crypto implementation doesn't use OpenSSL's engine api. Because of this any crypto
instructions on modern day cpu's are not used.

I've created this to see what the speed improvement is, and to test how to put things in a Erlang 
style api.
