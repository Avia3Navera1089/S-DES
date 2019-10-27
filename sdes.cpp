/*
    Author: Tanner Oliver
    CPSC370 1:45pm Class
    Email: toliver3@live.esu.edu
    October 20, 2019
    S-DES Encryption Algorithm
*/

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

using namespace std;
class SDES {
    public:
    SDES(string, string);
    void encrypt();
    void decrypt();
    void split();
    vector<int> expansion(vector<int> &);
    void EX_OR(vector<int> &, vector<int> &);
    vector<int> stringToVector(string);
    vector<int> sBoxIntToVector(int, int);
    void sbox(vector<int> &);
    void cycleKey();
    void reverseCycleKey();
    void print();

    private:
    vector<int> ptext;
    vector<int> rtext;
    vector<int> ltext;
    vector<int> tmptext;
    vector<int> keyVec;
    vector<int>::iterator it;
    int round_counter;
};

int main() {
    string key = "111000111";
    string plaintext = "100010110101";
    SDES cipher(key, plaintext);

    // Item #1: encrypt & decrypt once
    cipher.encrypt();
    cipher.decrypt();

    // Item #2: encryption & decryption rounds 2,3, and 4
    cipher.encrypt();
    cipher.encrypt();
    cipher.encrypt();
    cipher.encrypt();
    cipher.decrypt();

    //system.("pause"); // Uncomment for Windows OS  
    return 0;
}

// Constructor
SDES::SDES(string key, string plaintext){
    keyVec = stringToVector(key);
    ptext = stringToVector(plaintext);
    split();
    round_counter = 0;
}

// Encrypts once, cycles key beforehand if it isn't the first ecryption
void SDES::encrypt(){
    cout << "\n~~~ENCRYPTION~~~\n";
    if(round_counter == 0) {
        tmptext = rtext;
        expansion(rtext);
        EX_OR(rtext, keyVec);
        sbox(rtext);
        EX_OR(rtext, ltext);
        ltext = tmptext;  
    }
    else {
        tmptext = rtext;
        cycleKey();
        expansion(rtext);
        EX_OR(rtext, keyVec);
        sbox(rtext);
        EX_OR(rtext, ltext);
        ltext = tmptext;
    }
    
    round_counter++;
    print();
}

// Decrypts until plantext is found
void SDES::decrypt(){
    cout << "\n~~~DECRYPTION~~~\n";
    while(round_counter > 0) { 
        tmptext = ltext;
        expansion(ltext);
        EX_OR(ltext, keyVec);
        sbox(ltext);
        EX_OR(ltext,rtext);
        rtext = tmptext;
        round_counter--;
        if(round_counter >= 1){
            reverseCycleKey();
            print();
        }
    }
    
    cout << "--------------------------------------------------\n";
    cout << "~~~RESULTS~~~\n" << "\tPLAIN-TEXT:\t";
    for(it = ltext.begin(); it < ltext.end(); it++)
        cout << *it << ' ';
        
    cout << "- "; //endl;
   
    for(it = rtext.begin(); it < rtext.end(); it++)
        cout << *it << ' ';
    
    cout << "\n\tKEY:\t\t";
    for(it = keyVec.begin(); it < keyVec.end(); it++)
        cout << *it << ' ';        
    cout << "\n--------------------------------------------------\n" << endl;
}

// Split plaintext into two 6 bit arrays
void SDES::split(){
    for(int i = 0; i < 12; i++){
        if(i < 6)
            ltext.push_back(ptext.at(i));
        else
            rtext.push_back(ptext.at(i));
    }
}

// Performs the S-DES expansion function, 6 bits to 8 bits
vector<int> SDES::expansion(vector<int> &text){
    vector<int>::iterator it;
    
    int pos3 = text.at(2);
    int pos4 = text.at(3);

    it = text.begin() + 2;
    text.insert(it, pos4);
    it = text.begin() + 5;
    text.insert(it, pos3);
   
    return text;
}

// assigns vec1 the value of vec1 XOR vec2, will only iterate over vec2 for the number of elements in vec1 
// (useful for XORing 8 element rtext with 9 element key)
void SDES::EX_OR(vector<int> &vec1, vector<int> &vec2){ 
    for(int i = 0; i < vec1.size(); i++)
        vec1[i] ^= vec2[i];
}

// Parses a given string of bits into a vector
vector<int> SDES::stringToVector(string num){
    int bit;
    char c;
    vector<int> vec;
    stringstream iss(num);
    while(iss.get(c)){
        bit = (int)c - '0';
        vec.push_back(bit);
    }
    return vec;
        
}

// Takes an integer and parses its binary value into a vector digit by digit (includes leading zeroes)
vector<int> SDES::sBoxIntToVector(int num1, int num2){
    vector<int> vec;
    
    int i = 0;
    unsigned j;
    
    // parses 1's and 0's from sbox return values into vector f(R0 XOR K1)
    for(j = 1 << 2; j > 0; j = j / 2, i++){
        (num1 & j)? vec.push_back(1) : vec.push_back(0);
    }
    for(j = 1 << 2; j > 0; j = j / 2, i++){
        (num2 & j)? vec.push_back(1) : vec.push_back(0);
    }

    return vec;
}

// Defines s-boxes, modifies vector given in argument to reflect the contents of corresponding s-boxes
void SDES::sbox(vector<int> &text) {
    int sbox1[2][8] = { {5, 2, 1, 6, 3, 4, 7, 0},   // S-boxes 1 and 2, binary values replaced with equivalent integers for ease of use 
                        {1, 4, 6, 2, 0, 7, 5, 3} };
    int sbox2[2][8] = { {4, 0, 6, 5, 7, 1, 3, 2}, 
                        {5, 3, 0, 7, 6, 2, 1, 4} };
    int s1row = text[0], s2row = text[4];
    int s1col =  (((((0 | text[1]) << 1)            // Using some bit magic to find column number
                        | text[2]) << 1)            // Takes three inividual bits from a vector and turns them into a single integer value
                        | text[3]);
    int s2col =  (((((0 | text[5]) << 1) 
                        | text[6]) << 1) 
                        | text[7]);
    text = sBoxIntToVector(sbox1[s1row][s1col], sbox2[s2row][s2col]);   // returns value of s-boxs concatenated as a vector
}

// Shifts key left for encryption
void SDES::cycleKey() {
    int temp = keyVec[0];
    int i;
    for(i = 0; i < keyVec.size() - 1; i++) {
        keyVec.at(i) = keyVec.at(i+1);
    }
    keyVec.at(i) = temp;
}

// Shifts key right for decryption
void SDES:: reverseCycleKey() {
    int temp = keyVec.back();
    int i;
    for(i = keyVec.size() - 1; i > 0; i--) {
        keyVec.at(i) = keyVec.at(i-1);
    }
    keyVec.at(i) = temp;
}

void SDES::print() {
    cout << "Round #" << round_counter << endl;

    cout << "\tCIPHER-TEXT:\t";
   
    // Displaying rtext first then ltext: Ci = RiLi
    for(it = rtext.begin(); it < rtext.end(); it++)
        cout << *it << ' '; 
    cout << "- "; //endl;
   
    for(it = ltext.begin(); it < ltext.end(); it++)
        cout << *it << ' ';
    
    cout << "\n\tKEY #" << round_counter << ":\t\t";
    for(it = keyVec.begin(); it < keyVec.end() - 1; it++)
        cout << *it << ' ';        
    cout << endl;
}

