# nshdigest 


Simple OpenSSL based SHA performance test tool.
Just run it specifying a larger file.
To create a 1 GB file use the following command:

```
dd if=/dev/urandom of=1gb.bin bs=1M count=1024 status=progress
```

