# helloSealing - Simple Sealing Source Code with SGXSDK

This program seals your input and unseals sealed input.  
Sealing policy also can be designated with `MRENCLAVE` or `MRSIGNER`.

## Install
If your environment supports hardware mode, just execute following to build:

```
make
```

If you only can run simulation mode, execute following command to build:

```
make SGX_MODE=SIM
```

## Run program
Run the built program by following command:

```
./app
```
After launch, you will be asked which would you like to operate, sealing or unsealing.  

### Sealing
If you selected sealing, next you will be asked which policy would you like to select, `MRENCLAVE` or `MESIGNER`.  

After that, input some characters which you'd like to seal.  

The sealing will be executed and sealed data will be output as `sealed.dat` in current directory.

### Unsealing
If you selected unsealing, sealed data will be automatically loaded from `sealed.dat`.  

Then unsealing will be executed and the unsealed data (=input which you entered at the time of sealing) will be displayed.

## LICENSE
MIT license is adopted for this project.
In addition to that, "Makefile" also follows Intel's certain license.
For detail of Intel's OSS license see [here](https://github.com/intel/linux-sgx/blob/master/License.txt).
