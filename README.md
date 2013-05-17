crypto_challenge
================

Matasano Crypto Challenge

http://www.matasano.com/articles/crypto-challenges/

You Should Do The Matasano Crypto Challenges
--------------------------------------------

We've built a collection of 48 exercises that demonstrate attacks on real-world crypto.

This is a different way to learn about crypto than taking a class or reading a book. We give you problems to solve. They're derived from weaknesses in real-world systems and modern cryptographic constructions. We give you enough info to learn about the underlying crypto concepts yourself. When you're finished, you'll not only have learned a good deal about how cryptosystems are built, but you'll also understand how they're attacked.

HOW DOES THIS WORK?
-------------------
You mail cryptopals at matasano.com. Just say you want in.

WAIT, WHAT?
-----------
Yes: you actually compose an email.

AND THEN WHAT HAPPENS?
----------------------
We send challenges, 8 at a time. You send results. We send more.

There's no grading. We probably won't run your code (we'll definitely read it though). You can ask us for help; we'll try our best.

If you make it through all six sets, we'll try to make a $20 donation to Watsi or Partners in Health for you. Both are very cool and you should check them out. But also, do the challenges because they're neat.

WHAT ARE THE RULES?
-------------------
Just one: please don't share what we send you, or your answers. This process doesn't work if you can just grab code off Github to solve your problems. In fact, we've had to make some of our challenges slightly less realistic to keep that from happening. If you don't think you can do this without posting the challenges or your answers, please wait for us to publish them sometime in the future.

HOW MUCH MATH DO I NEED TO KNOW?
--------------------------------
If you have any trouble with the math in these problems, you should be able to find a local 9th grader to help you out. It turns out that many modern crypto attacks don't involve much hard math.

HOW MUCH CRYPTO DO I NEED TO KNOW?
----------------------------------
None. That's the point.

SO WHAT DO I NEED TO KNOW?
--------------------------
You'll want to be able to code proficiently in any language. We've received submissions in C, C++, Python, Ruby, Perl, Visual Basic, X86 Assembly, Haskell, and Lisp. Surprise us with another language. Our friend Maciej says these challenges are a good way to learn a new language, so maybe now's the time to pick up Clojure or Rust.

WHAT SHOULD I EXPECT?
---------------------
Right now, we have six sets. They get progressively harder. Again: these are based off real-world vulnerabilities. None of them are "puzzles". They're not designed to trip you up. Some of the attacks are clever, though, and if you're not familiar with crypto cleverness... well, you should like solving puzzles. An appreciation for early-90's MTV hip-hop can't hurt either.

CAN YOU GIVE US A LONG-WINDED INDULGENT DESCRIPTION FOR WHY YOU'VE CHOSEN TO DO THIS?
-------------------------------------------------------------------------------------
It turns out that we can.

If you're not that familiar with crypto already, or if your familiarty comes mostly from things like Applied Cryptography, this fact may surprise you: most crypto is fatally broken. The systems we're relying on today that aren't known to be fatally broken are in a state of just waiting to be fatally broken. Nobody is sure that TLS 1.2 or SSH 2 or OTR are going to remain safe as designed.

The current state of crypto software security is similar to the state of software security in the 1990s. Specifically: until around 1995, it was not common knowledge that software built by humans might have trouble counting. As a result, nobody could size a buffer properly, and humanity incurred billions of dollars in cleanup after a decade and a half of emergency fixes for memory corruption vulnerabilities.

Counting is not a hard problem. But cryptography is. There are just a few things you can screw up to get the size of a buffer wrong. There are tens, probably hundreds, of obscure little things you can do to take a cryptosystem that should be secure even against an adversary with more CPU cores than there are atoms in the solar system, and make it solveable with a Perl script and 15 seconds. Don't take our word for it: do the challenges and you'll see.

People "know" this already, but they don't really know it in their gut, and we think the reason for that is that very few people actually know how to implement the best-known attacks. So, mail us, and we'll give you a tour of them.

THAT'S IT?
----------
Also if you can breeze through these we'd probably love to try to hire you. But don't worry: we're not recruiters and we're not jerks. (Incidentally, if you're interested in the kind of work we do, don't wait to get through the challenges to contact us.)
