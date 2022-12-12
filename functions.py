
import random as rd
import hashlib 
import math

#The goal of this function is to optimize the gcd function
#Since the Euclidean algorithm is the fastest way to calculate the gcd, we will be using that algorithm in our function

class pubkey:
    def __init__(self,x,y):
        self.n=x
        self.e=y
class secretkey:
    def __init__(self,x,y,z):
        self.d=x
        self.p=y
        self.q=z

#Here we are creating a function that will calculate the operation : x**s%n.
#Since with s sufficiently big it can be difficult for the computer to calculate x**s directly
#We simplify this calculation by decomposing x**s%n into a product of x**(k*10**i)%n since we have (a*b)%n=((a%n)*(b%n))%n


def optimized_power(x,s,n): 
    str_s=str(s)
    dec_power_s=[int(x) for x in str_s]           #This is a list that will contains all the decimal values of s
    dec_power_s.reverse()                         #We reverse the list so it will start from the lowest power of 10 to the highest
    x_power_ten=x%n               #This value will be equal to x**(10**i)
    result=1
    for i in range(len(dec_power_s)):
        result=int((result*(int(x_power_ten**dec_power_s[i])%n))%n)
        x_power_ten=int(((x_power_ten**10))%n)
    return result

#This function calculates the gcd using the Euclidean algorithm
def gcd(a,b):       
    if a==0 and b==0:
        print("Error : Both arguments are equal to zero")
        return 0
    if a>b:
        min_a_b=b
        max_a_b=a
    else:
        min_a_b=a
        max_a_b=b     
    while min_a_b!=0:
        c=max_a_b%min_a_b   
        max_a_b=min_a_b
        min_a_b=c
    return max_a_b      #max_a_b is equal to the before last remainder of the Euclidean algorithm 

#The fastest way to calculate the modular multiplicative inverse is too use the extended Euclidean Algorithm
def multiplicative_modular_inverse(a,b):
    q_list=[]
    r_list=[]
    x=a
    y=b
    while y!=0: #We first apply the Euclidean Algorithm
        r=x%y
        q=x//y
        q_list.append(q)           #This list will contains all the quotients of the Euclidean algorithm
        x=y
        y=r
    if x==1:    #Then if the gcd is equal to 1, we calculate the Bezout coefficients by reversing the Euclidean algorithm
        sn=1
        sn1=0
        tn=0
        tn1=1
        for i in range(1,len(q_list)):
            qi=q_list[-i]
            s=sn1
            t=tn1
            sn1=sn-qi*sn1
            tn1=tn-qi*tn1
            sn=s
            tn=t
        if sn1<0:           #We want to have a positive value since when this function provides negative values, it tends to slow down the functions using the output
            sn1+=b
        return sn1
    else:
        print("There is no modular multiplicative inverse for "+str(a)+" with the modulo "+str(b))
#In order to check if a number is prime or not we check every number from 1 to it's square root can divide it or not
#If that's not the case then it is prime
def isprime(a):

    bool=True
    squ_a=int(math.sqrt(a))
    i=2
    while i<=squ_a and bool==True:
        s=a%i
        if s==0:
            bool=False
        i+=1
    return bool

def generate_Keys(path_secret,path_pub):
    easy=10**(-13)
    print("Before finding a random p ")
    p=rd.randint(10**14,10**17)                            #p=rd.randint((10**22)*easy,(10**27)*easy)  #We first generate p and q
    q=rd.randint(10**14,10**17)
    bool=False
    print("Before looking at the prime level of p ")
    while bool==False:
        p+=1
        bool=isprime(p)
    bool=False
    print("Before calculating q")
    while bool==False:
        q+=1
        bool=isprime(q)
    print("Before calculating n")
    n=p*q                               #With p and q we get n
    e=rd.randint(0,2*n)                #We then generate e
    phi_n=(p-1)*(q-1)
    bool=False
    while bool==False:
        e+=1
        bool=gcd(e,phi_n)==1
    print("Before calculating d")
    d=multiplicative_modular_inverse(e,phi_n)
    pub_file=open(path_pub,"w")
    Pub_content=str(n)+'##'+str(e)
    pub_file.write(Pub_content)
    pub_file.close()
    secret_file=open(path_secret,'w')
    Secret_content=str(d)+'##'+str(p)+'##'+str(q)
    secret_file.write(Secret_content)
    secret_file.close()
    pub_key_1=pubkey(n,e)
    secret_key_1=secretkey(d,p,q)
    return [pub_key_1,secret_key_1]

def Sign(pub_key,secret_key,signable,isFile=False):
    if isFile!=True:
        b_signable=signable.encode()
        hash=hashlib.sha256(b_signable)
    else:
        path=signable
        signable_file=open(path,"rb")
        b_content_file=signable_file.read()
        signable_file.close()
        hash=hashlib.sha256(b_content_file)
    hash=hash.hexdigest()
    hash=int(hash,16)
    pr_hash=hash%pub_key.n
    pr_hash=hex(int(pr_hash))
    signed=optimized_power(hash,secret_key.d,pub_key.n)  
    signed=hex(int(signed))
    return signed

def Verify_Signature(public_key,signed_object,hash_object=None,object=None,isFile=False):
    signed_object=int(signed_object,16)
    hash=optimized_power(signed_object,public_key.e,public_key.n)
    hash=hex(int(hash))
    if hash_object is None and object is None:
        return hash
    elif object is None:
        return hash==hash_object
    elif hash_object is None and isFile==False:
        b_object=object.encode()
        hash_object=hashlib.sha256(b_object)
    elif hash_object is None and isFile:
        path=object
        signable_file=open(path,"rb")
        b_content_file=signable_file.read()
        hash_object=hashlib.sha256(b_content_file)
        signable_file.close()
    hash_object=hash_object.hexdigest()
    hash_object=int(hash_object,16)
    hash_object=int(hash_object%public_key.n)
    hash_object=hex(int(hash_object))
    return hash==hash_object


def import_Keys(path,type):
    if type=='secret':
        secret_file=open(path,'r')
        secret_contents=secret_file.read().split('##')
        d=int(secret_contents[0])
        p=int(secret_contents[1])
        q=int(secret_contents[2])
        sec_key=secretkey(d,p,q)
        return sec_key
    else:
        public_file=open(path,'r')
        public_contents=public_file.read().split('##')
        n=int(public_contents[0])
        e=int(public_contents[1])
        public_key=pubkey(n,e)
        return public_key
        