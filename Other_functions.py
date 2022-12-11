import math
import random as rd
import decimal as deci
import DPS_Project
def isprime(a):
    bool=True
    squ_a=int(math.sqrt(a))
    i=2
    while i<=squ_a+1 and bool==True:
        s=a%i
        if s==0:
            bool=False
        i+=1
    return bool

def import_Keys(path,type):
    if type=='secret':
        secret_file=open(path,'r')
        secret_contents=secret_file.read().split('##')
        d=int(secret_contents[0])
        p=int(secret_contents[1])
        q=int(secret_contents[2])
        sec_key=DPS_Project.secretkey(d,p,q)
        return sec_key
    else:
        public_file=open(path,'r')
        public_contents=public_file.read().split('##')
        n=int(public_contents[0])
        e=int(public_contents[1])
        public_key=DPS_Project.pubkey(n,e)
        return public_key
        


#Here we are creating a function that will calculate the operation : x**s%n.
#Since with s sufficiently big it can be difficult for the computer to calculate x**s directly
#So we simplify this calculation by decomposing x**s%n into a product of x**(k*10**i)%n since we have (a*b)%n=((a%n)*(b%n))%n

# def optimized_power(x,s,n): 
#     dec_power_s=[]           #This is a list that will contains all the decimal values of s
#     dec=1
#     while s//dec!=0:
#         dec=dec*10
#     dec=dec/10 
#     sp=s
#     while dec>0.1:
#         dec_s=int(sp//dec)
#         dec_power_s.append(dec_s)
#         sp-=dec*dec_s
#         dec/=10
#     dec_power_s.reverse()       #We reverse the list so it will start from the lowest power of 10 to the highest
#     x_power_ten=x%n               #This value will be equal to x**(10**i)
#     result=1
#     for i in range(len(dec_power_s)):
#         result=int((result*(int(x_power_ten**dec_power_s[i])%n))%n)
#         x_power_ten=int(((x_power_ten**10))%n)
#     return result
Falses=0
Trues=0
# for i in range(1):
#     a=rd.randint(2,12)
#     b=rd.randint(10**3,10**4+3)
#     c=rd.randint(134,100000)
#     x1=int((a**b)%c)
#     x2=optimized_power(a,b,c)
#     if(x1==x2):
#         Trues+=1
#     else:
#         print("False !!!!!")
# print(Trues)
print(Falses)
# d=241
# e=1741
# n=2325
# s=(150**(241))%2325
# s=(s**1741)%n
# print(s)
# dp=1013
# ep=2141
# np=3185
# sp=(150**dp)%np
# sp=(sp**ep)%np
# ep*dp
# d=381723064243440833           #d=381723064243440811
# e=450917220631632151
# n=469054850113965677
# p=728277959
# q=644060203
# print(isprime(p))
# print(isprime(q))
# s=optimized_power(70,d,n)
# print(optimized_power(s,e,n))
# d=34928
# str_d=str(d)
# decimals=[int(x) for x in str_d]
# decimals.reverse()
# print(decimals)