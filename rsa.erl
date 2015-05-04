-module(rsa).
-compile(export_all).

%%
%% Program entry.
%%
main() ->
	{N, D, E} = gen_keys(512),
	A		  = io:get_line("Enter a message: "),
	C		  = encrypt(A, E, N),
	Ad		  = decrypt(C, D, N),
	io:fwrite("Message, decrypted: ~s~n", [Ad]).

%%
%% Concurrently generates P and Q, and thus N. P and Q will be
%% "BitSize" bits in size, and thus N should be roughly twice that
%% many bits. E defaults to 65537 as in many implementations.
%%
gen_keys(BitSize) ->
	spawn(rsa, gen_prime, [self(), BitSize]),
	spawn(rsa, gen_prime, [self(), BitSize]),
	receive P -> P end,
	receive Q -> Q end,
	E		  = 65537,
	N		  = P * Q,
	Phi		  = (P - 1) * (Q - 1),
	{1, _, D} = gcd(Phi, E),
	{N, D, E}.

%%
%% Thread subroutine to generate a random prime number of the
%% specified bitsize.
%%
gen_prime(Pid, BitSize) ->
	random:seed(now()),
	Pg = next_prime(gen_num(BitSize)),
	Pid ! Pg.

%%
%% Given a candidate number, use modular exponentiation to
%% determine if the number is prime. There is a (very small)
%% chance of a false positive, as the modular exponentiation
%% primality test also works for so-called "pseudo prime" numbers.
%%
next_prime(Pc) ->
	Pc_odd = case Pc band 1 of
				 0 -> Pc + 1;
				 1 -> Pc
			 end,
	Exp = mod_exp(2, Pc_odd - 1, Pc_odd),
	case Exp of
		1 -> Pc_odd;
		_ -> next_prime(Pc_odd + 2)
	end.

%%
%% Generates a random number of the specified number of bits. This
%% starts with the number 1, shifts it left by a bit, adding a
%% random bit, and continuing until reaching the given bitsize.
%%
gen_num(BitSize)	  -> gen_num(BitSize, 1).
gen_num(BitSize, Acc) ->
	if
		Acc > (1 bsl (BitSize - 1)) -> Acc;
		true -> gen_num(BitSize, Acc bsl 1 + (random:uniform(2) - 1))
	end.

%%
%% Raises A to the K using mod-N arithmetic. This uses an
%% efficient divide-and-conquer algorithm that works on very large
%% numbers (hundreds of digits) in logarithmic time.
%%
mod_exp(_, 0, _) -> 1;
mod_exp(A, K, N) ->
	Temp   = mod_exp(A, K div 2, N),
	Result = (Temp * Temp) rem N,
	if
		K rem 2 == 1 -> (Result * A) rem N;
		true		 -> Result
	end.

%%
%% This is an extended version of the well known Euclidean GCD
%% algorithm. This version returns the residual S and T values; T
%% is used for D, the decryption exponent, in RSA.
%%
gcd(A, B)						-> gcd(A, B, 1).
gcd(0, B, C) when C band 1 == 1 -> {B, 1, 1};
gcd(0, B, _)					-> {B, 0, 1};
gcd(A, 0, C) when C band 1 == 1 -> {A, 1, 1};
gcd(A, 0, _)					-> {A, 1, 0};
gcd(A, B, C)					->
	Q			  = A div B,
	R			  = A rem B,
	{Gcd, Sp, Tp} = gcd(B, R, C + 1),
	{Gcd, Tp, Sp - Q * Tp}.

%%
%% RSA encryption: raise a message A to the power E using modular
%% N arithmetic.
%%
encrypt(A, E, N) -> mod_exp(str_to_int(A), E, N).

%%
%% RSA decryption: raise an encrypted message C to the power D
%% using modular N arithmetic.
%%
decrypt(C, D, N) -> int_to_str(mod_exp(C, D, N)).

%%
%% Convert a string to an integer so it can be operated on
%% mathematically.
%%
str_to_int([F | R])			-> str_to_int(F, R).
str_to_int(Result, [])		-> Result;
str_to_int(Result, [F | R]) -> str_to_int(Result bsl 8 + F, R).

%%
%% Convert a number to a string (the reverse of the str_to_int()
%% function above).
%%
int_to_str(Num)		 -> int_to_str([], Num).
int_to_str(Str, 0)	 -> Str;
int_to_str(Str, Num) -> int_to_str([Num band 255 | Str], Num bsr 8).

