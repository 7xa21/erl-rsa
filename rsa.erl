-module(rsa).
-compile(export_all).

main() ->
	{N, D, E} = gen_keys(512),
	A		  = io:get_line("Enter a message: "),
	C		  = encrypt(A, E, N),
	Ad		  = decrypt(C, D, N),
	io:fwrite("Message, decrypted: ~s~n", [Ad]).

gen_keys(BitSize) ->
	spawn(rsa, gen_prime, [self(), BitSize]),
	spawn(rsa, gen_prime, [self(), BitSize]),
	P		  = receive P -> P end,
	Q		  = receive Q -> Q end,
	E		  = 65537,
	N		  = P * Q,
	Phi		  = (P - 1) * (Q - 1),
	{1, _, D} = gcd(Phi, E),
	{N, D, E}.

gen_prime(Pid, BitSize) ->
	random:seed(now()),
	Pg = next_prime(gen_num(BitSize)),
	Pid ! Pg.

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

gen_num(BitSize)	  -> gen_num(BitSize, 1).
gen_num(BitSize, Acc) ->
	if
		Acc > (1 bsl (BitSize - 1)) -> Acc;
		true -> gen_num(BitSize, Acc bsl 1 + (random:uniform(2) - 1))
	end.

mod_exp(_, 0, _) -> 1;
mod_exp(A, K, N) ->
	Temp   = mod_exp(A, K div 2, N),
	Result = (Temp * Temp) rem N,
	if
		K rem 2 == 1 -> (Result * A) rem N;
		true		 -> Result
	end.

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

encrypt(A, E, N) -> mod_exp(str_to_int(A), E, N).

decrypt(C, D, N) -> int_to_str(mod_exp(C, D, N)).

str_to_int([F | R])			-> str_to_int(F, R).
str_to_int(Result, [])		-> Result;
str_to_int(Result, [F | R]) -> str_to_int(Result bsl 8 + F, R).

int_to_str(Num)		 -> int_to_str([], Num).
int_to_str(Str, 0)	 -> Str;
int_to_str(Str, Num) -> int_to_str([Num band 255 | Str], Num bsr 8).