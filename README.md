# JHRSAEncoder
RSA encode with openssl

## a note:
![image](https://github.com/xjh093/JHRSAEncoder/blob/master/warning.png)

the file ``libcrypto.a`` in openssl cann't upload, because it's 36.6MB

if can't find header file: add the path of folder ``JHRSAEncoder`` in `Header Search Path`


## example1: string length is less than 117 
because of PADDING (128 - 11)

```
    NSString *content = @"Hello,JHRSAEncoder";
    NSString *encodeString = [JHRSAEncoder jh_encodeMAXString:content withPublicKey:@"rsa_public_key"];
    NSLog(@"encodeString:%@",encodeString);
    // encodeString:EkM5Txbfm9SFm8EgAHAxgt/xaq/RY/KGLYF4MF/x0ok5emSMobZHmXL5Z0q8137KvNKsd6llfRksr3Jv1w783F1aNxDG89rXtfThKbb5+/S+k3OhunuL2i+ftJzly62norcwC78SIa3H0VB7x3QlZbq2yOruWjEI79Q9AJIHCnA=
    
    NSString *decodeString = [JHRSAEncoder jh_decodeMAXString:encodeString withPrivateKey:@"rsa_private_key"];
    NSLog(@"decodeString:%@",decodeString);
    // decodeString:Hello,JHRSAEncoder
```

## example2: string length is more than 117

```
    NSString *content = @"Hello,JHRSAEncoder"
    "000000000000000000000000000000"
    "111111111111111111111111111111"
    "222222222222222222222222222222"
    "333333333333333333333333333333"
    "444444444444444444444444444444"
    "555555555555555555555567890asd";
    
    NSString *encodeString = [JHRSAEncoder jh_encodeMAXString:content withPublicKey:@"rsa_public_key"];
    NSLog(@"encodeString:%@",encodeString);
    // encodeString:TT5odaHy5K/YqcV2B1FE9CbNP6kwV17absJkVlct7/Zwp89dg9lut1ZGtuCICUJK1wbGIqb5+n8HPD2h6NYY3KPAmUAmw+DTmygn0EbXa2JAHv0DMMYLRxcOq4YG6xFpGdt0agu/GSMFyTkDCLGmeP3J3Y7hHQ3ks7ZJw+TjJSo=Gu/glzcO+NZR6TChrkDeRSnpkNoW3aP7xWN5EH+Wl6DwHBFZBrAFncChFeZDTRpFI2+mQbEALHnLZsTNaJtRjzb95DTQi4WJPhUwwgF3m1REdMzPxR7YfV+ZJUrIeJJfuSQRsVPuspYo4tyuXWz2SdXpiSLlwN93WyJO49slz2A=
    
    NSString *decodeString = [JHRSAEncoder jh_decodeMAXString:encodeString withPrivateKey:@"rsa_private_key"];
    NSLog(@"decodeString:%@",decodeString);
    // decodeString:Hello,JHRSAEncoder000000000000000000000000000000111111111111111111111111111111222222222222222222222222222222333333333P333333333333333333333444444444444444444444444444444555555555555555555555567890asd

```
