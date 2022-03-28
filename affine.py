from base64 import decode
from cgitb import text
from cmath import inf
from re import A
import sys
import numpy as np

def main():
    validbit = 1
    mode = sys.argv[1]
    inFile, outFile = sys.argv[2], sys.argv[3]
    deciphered = False
    
    if sys.argv[1] == "decipher":
        decipher(inFile, outFile, sys.argv[4])
        deciphered = True
        return
    
    
    if deciphered == False:
        a, b = int(sys.argv[4]), int(sys.argv[5])
        validbit, g, v = egcd(a, b)
        if validbit != 1:
            print("The key pair (" + str(a) + ", " +   str(b) + ") is invalid, please select another key.")
            return
        if mode == "encrypt":
            encrypt(inFile, outFile, a, b)
            return
        if mode == "decrypt":
            decrypt(inFile, outFile, a, b)
            return
        
def egcd(a, b):
        # as + bt = d and gcd(a, b) = d
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y) 

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g == 1:
        return x % m   

def encrypt(inFile, outFile, a, b):
    file, out = open(inFile, 'r'), open(outFile, 'w')
    
    # (a * m) + b % 128
    for line in file:
        for character in line:
            encodedChar = (128 + a * (ord(character) + b)) % 128
            out.write(chr(encodedChar))
    file.close()
    out.close()
    
def decrypt(inFile, outFile, a, b):
    file, out = open(inFile, 'r'), open(outFile, 'w')
    
    # (modinverse(a) * m) - b % 128
    for line in file:
        for character in line:
            decodedChar = (128 + modinv(a, 128) * ord(character) - b) % 128
            if decodedChar == 123:
                out.write("b")    
            elif decodedChar == 5:
                out.write("\n")
            else:
                out.write(chr(decodedChar))
    file.close()
    out.close()

def checkMatches(inFile, dictionary, a, b):
    file, words = open(inFile, 'r'), open(dictionary, 'r')
    temp = ""
    wordCount = 0
    
    for line in file:
        for character in line:
            decodedChar = (128 + modinv(a, 128) * ord(character) - b) % 128
            # print(chr(decodedChar))
            if decodedChar == 123:
                temp += "b"    
            elif decodedChar == 5:
                temp += "\n"
            else:
                temp += chr(decodedChar)
                
    decodedList = temp.split()
    
    for line in words:
        for decode in decodedList:
            if len(decode) > 3:
                if decode.lower() == line.strip("\n").lower():
                    wordCount += 1
                    print("Word " + str(wordCount) + " " + "Matched With Key " + str(a) + ", " + str(b) + ".")

    return wordCount

def decipher(inFile, outFile, dictionary):
    file, out = open(inFile, 'r'), open(outFile, 'w')
    currentWordCount = 0
    currentA = 0
    currentB = 0
    
    for a in range(128):
        for b in range(128):
            if egcd(a, 128)[0] == 1 and egcd(a, b)[0] == 1:
                count = checkMatches(inFile, dictionary, a, b)
                print(count)
                if count > currentWordCount:
                    currentA = a
                    currentB = b
                    currentWordCount = count
                    
    out.write(str(currentA) + " " + str(currentB) + "\n")
    out.write("DECODED MESSAGE:\n")

    for line in file:
        for character in line:
            decodedChar = (128 + modinv(currentA, 128) * ord(character) - currentB) % 128
            if decodedChar == 123:
                out.write("b")    
            elif decodedChar == 5:
                out.write("\n")
            else:
                out.write(chr(decodedChar))
    
    file.close()
    out.close()

if __name__ == "__main__":
    main()