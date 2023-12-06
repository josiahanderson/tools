def palindrome(word):
    left = 0;
    right = len(word) - 1;
    for char in word:
        #print(word[left] + " : " + word[right])
        if word[left] != word[right]:
            return word + " is NOT a palindrome!"
        left += 1
        right -= 1
    return word + " IS a palindrome!"

word = input("Please enter a word to determine if it is a palindrome: ")
print(palindrome(word))
