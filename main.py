
import functions
from os.path import exists
def main():
    answer=3
    has_public_key=False
    has_secret_key=False
    ending="\n>>>> "
    print("                                                                          RSA: Signature\n")
    print("This is a program designed to sign strings and files using the RSA algorithm\n")
    while(answer!=5):
        print("\nWhat do you want to do ?")
        print("Answer 1 if you want to create a set of keys")
        print("Answer 2 if you want to import a set of keys from files")
        print("Answer 3 if you want to sign a string or a file")
        print("Answer 4 if you want to verify a signature for a file or a string")
        print("Answer 5 if you want to exit the program")
        answer=functions.correct_input(ending,1,1,5)
        if answer==1:
            filename_pub=''
            incorrect_path=True
            while filename_pub=='' and incorrect_path:
                filename_pub=input("What shall be the path to the file containing the public key : "+ending)
                incorrect_path=exists(filename_pub)
            filename_secret=''
            incorrect_path=True
            while filename_secret=='':
                filename_secret=input("What shall be the path to the file containing the secret key : "+ending)
                incorrect_path=exists(filename_pub)
            strength=11
            while strength<1 or strength>10:
                try:
                    strength=int(input("What shall be the strength of your keys ? Pick a number between 1 and 10 "+ending))
                except:
                    strength=12
                    print("Error: Wrong type of answer ")
            print("Generating keys....")
            [Pub_Key,Secret_Key]=functions.generate_Keys(filename_secret,filename_pub,strength)
            has_public_key=True
            has_secret_key=True

            print("The public and secret key have been generated and can now be used")
        elif answer==2:
            Files_chosen=functions.correct_input('Answer 1 if you just want to import a public key \nAnswer 2 if you want to import both keys '+ending,1,1,2)
            if Files_chosen==2:
                filename_secret=''
                incorrect_path=True
                while filename_secret=='' and incorrect_path:
                    filename_secret=input("What is the path of the file containing the secret key : ")
                    incorrect_path=exists(filename_secret)
                Secret_Key=functions.import_Keys(filename_secret,'secret')
                has_secret_key=True
            filename_pub=''
            incorrect_path=True
            while filename_pub=='' and incorrect_path:
                filename_pub=input("What is the path of the file containing the public key : ")
                incorrect_path=exists(filename_pub)
            Pub_Key=functions.import_Keys(filename_pub,'public')
            has_public_key=True
        elif answer==3:
            if has_public_key and has_secret_key:
                isFile=functions.correct_input('Answer 1 if you want to sign a file \nAnswer 2 if you want to sign a string '+ending,1,1,2)
                if isFile==1:
                    filename=functions.correct_input('What is the path of the file ? '+ending,2)
                    print("The signature of the file is :"+str(functions.Sign(Pub_Key,Secret_Key,filename,True)))
                else:
                    object=functions.correct_input('What is the string you want to sign ?'+ending,3)
                    print("The object is : "+object)
                    print("The signature of the string is : "+str(functions.Sign(Pub_Key,Secret_Key,object)))
            else:
                print("You don't have a secret key or a public key. Please generate one or import one before you can sign.")
        elif answer==4:
            if has_public_key:
                Signature=None
                while Signature is None:
                    Signature=input("What is the signature ?"+ending)
                has_object=functions.correct_input("Do you have the file or the string ?\nAnswer 1 if you do"+ending,1)
                if has_object==1:
                    isFile=functions.correct_input('Answer 1 if you want to verify the signature of a file \nAnswer 2 if you want to verify the signature of a string '+ending,1,1,2)
                    if isFile==1:
                        filename=functions.correct_input('What is the path of the file ? '+ending,2)
                        Correct_Signature=functions.Verify_Signature(Pub_Key,Signature,None,filename,isFile=True)
                        if Correct_Signature:
                            print("The signature does correspond to the file")
                        else: 
                            print("The signature does not correspond to the file")
                    else:
                        object=functions.correct_input('What is the string ?'+ending,3)
                        print("The object is :"+object)
                        Correct_Signature=functions.Verify_Signature(Pub_Key,Signature,None,object,isFile=False)
                        if Correct_Signature:
                            print("The signature does correspond to the string")
                        else: 
                            print("The signature does not correspond to the string")
                else:
                    print("This is the hash that can be obtained from verifying the signature : "+str(functions.Verify_Signature(Pub_Key,Signature)))
main()
