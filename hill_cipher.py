#!/usr/bin/env python2
#
# a script/tool to encrypt
# and decrypt using the
# hill cipher
#
# this is mostly working with matrices
# and i'm trying to implement as much
# in pure python (no external libraries)
# in order to also allow this to be
# python version-less
#
#
# Copyright Tiago Teixeira, 2019
#

#
# TODO
#
#	extend the key size to more sizes
#
#	check for key validity and automatically
#	change it to the "next" possible key
#

#
#
# THE ALPHABET BEING USED
# CHANGE THIS IF NEEDED
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
# or set --alphabet parameter
#
#
#

mhelp = """
Hill Cipher

Encryptor and decryptor

	%s <enc/dec> [options] -k <key> <text>

available options:
	-k, --key=<key>
		set the encryption key
		the original key in case of decryption

	-a, --alphabet=<new alphabet>
		specify a new alphabet to use

	-m, --matrix
		don't actually run, just print out
		the enc/dec matrix
"""

# this is the same in both versions
from math import sqrt

# generate a dictionary to simplify
# converting from letter to number
# (instead of using list.index)
#
# uses the global 'alphabet' constant
#
# sets the global r_alphabet
r_alphabet = {}
def __gen_rev():
	global r_alphabet
	r_alphabet = {}
	for i in range(len(alphabet)):
		r_alphabet[alphabet[i]] = i
# and in case someone forgets it
__gen_rev()

# removes a line and a column
# from a 3x3 matrix
#
# l and c are line and column, zero-based
#
# returns a new 2x2 matrix
def __rem_3x3(m,l,c):
	ret = []
	for i in range(3):
		if i==l:
			continue
		line = []
		for j in range(3):
			if j==c:
				continue
			line.append(m[i][j])
		ret.append(tuple(line))
	return tuple(ret)

# calculates the determinant
# of a 2x2 matrix
#
# returns an integer
def __det_2x2(m):
	return m[0][0]*m[1][1] - m[0][1]*m[1][0]

# calculates the determinant
# of a 3x3 matrix
#
# returns an integer
def __det_3x3(m):
	a = m[0][0]*__det_2x2(__rem_3x3(m,0,0))
	b = m[0][1]*__det_2x2(__rem_3x3(m,0,1))
	c = m[0][2]*__det_2x2(__rem_3x3(m,0,2))
	return a-b+c

# calculates the adjugate matrix
# of a 2x2 matrix
#
# returns a new matrix (tuple of tuples)
def __adj_2x2(m):
	return (
		(m[1][1],-m[0][1]),
		(-m[1][0],m[0][0])
	)

# calculates the adjugate matrix
# of a 3x3 matrix
#
# returns a new matrix (tuple of tuples)
def __adj_3x3(m):
	# adj(A) is the transpose of the cofactor matrix
	ret = (
		(
			# line 0
			__det_2x2(__rem_3x3(m,0,0)),
			-__det_2x2(__rem_3x3(m,1,0)),
			__det_2x2(__rem_3x3(m,2,0))
		),
		(
			# line 1
			-__det_2x2(__rem_3x3(m,0,1)),
			__det_2x2(__rem_3x3(m,1,1)),
			-__det_2x2(__rem_3x3(m,2,1))
		),
		(
			# line 2
			__det_2x2(__rem_3x3(m,0,2)),
			-__det_2x2(__rem_3x3(m,1,2)),
			__det_2x2(__rem_3x3(m,2,2))
		)
	)
	return ret

# finds the inverse of the given
# determinant modulo mod
#
# returns the inverse determinant (integer)
# or -1 if there is no inverse
def __inv_det(det,mod):
	# iterate from 1..mod
	det %= mod	# just to be sure
	for i in range(1,mod):
		# TODO simplify this comparison?
		if (i*det)%mod==1:
			return i
	return -1

# multiply a matrix by an integer
# modulo mod
#
# returns a new matrix
def __mul_int(m,k,mod):
	ret = []
	for line in m:
		nline = []
		for i in line:
			nline.append((i*k)%mod)
		ret.append(tuple(nline))
	return tuple(ret)

# multiply a NxN matrix
# against a 1xN matrix (a simple tuple/list)
# modulo mod
#
# returns the result matrix (tuple)
def __mul_mat(m,k,mod):
	ret = []
	n = len(k)
	for i in range(n):
		r = 0
		for j in range(n):
			r += m[i][j]*k[j]
		ret.append(r%mod)
	return tuple(ret)

#
# 'LOCAL' / HELPER FUNCTIONS ENDED
# FROM HERE, THIS IS IT
#

# generate a matrix key from the given input
# the input length must be a perfect square
#
# returns the matrix key (tuple of tuples)
# or None if is not perfect square
def gen_enc_key(ikey):
	s = sqrt(len(ikey))
	if int(s)!=s:
		# not a perfect square
		print("The key length is not a perfect square")
		return None
	s = int(s)
	index = 0
	key = []
	for i in range(s):
		line = []
		for i in range(s):
			k = ikey[index]
			index += 1
			try:
				line.append(r_alphabet[k])
			except KeyError:
				print("'%s' is not in the alphabet"%k)
				print("Maybe ou forgot to change the alphabet?")
				return None
		key.append(tuple(line))
	return tuple(key)

# get the decryption key from
# matrix key
#
# returns the new matrix
# or None on error
def gen_dec_key(key,mod):
	n = len(key)
	if n==3:
		mat = __adj_3x3(key)
		det = __inv_det(__det_3x3(key),mod)
	elif n==2:
		mat = __adj_2x2(key)
		det = __inv_det(__det_2x2(key),mod)
	else:
		# TODO implement a NxN option?
		print("Key size '%d' is not supported" % n)
		return None
	if det == None:
		print("Matrix can not be inverted")
		return None
	return __mul_int(mat,det,mod)

# executes a encryption/decryption
#
# since encryption and decryption are
# mathmatically the same, just the keys
# change, this can be implemented as only
# one function
#
# matrix is the key to use
# string is the string to encrypt/decrypt
# mod is the mod
#
# returns a string with the result
def execute(matrix,string,mod):
	n = len(matrix)
	
	# if needed, pad with the
	# first letter of the alphabet
	rem = len(string)%n
	string += rem*alphabet[0]
	s = len(string)
	
	# now split and multiply
	result = ""
	for i in range(0,s,n):
		step = ""
		part = string[i:i+n]
		# generate matrix
		mat = []
		for p in part:
			try:
				mat.append(r_alphabet[p])
			except KeyError:
				print("'%s' is not in the alphabet"%p)
				return ""
		# multiply them
		part = __mul_mat(matrix,mat,mod)
		# retrieve string
		for p in part:
			step += alphabet[p]
		
		result += step
	
	# done
	
	return result

# encrypt string using key
#
# this serves as a wrapper
#
# key is the string key
# string is the text to encrypt
#
# returns the encrypted string
def encrypt(key,string,mod):
	mkey = gen_enc_key(key)
	result = execute(mkey,string,mod)
	
	return result

# decrypt string encrypted with key
#
# this serves as a wrapper
#
# key is the original key string
# string is the text to be decrypted
#
# returns the decrypted string
def decrypt(key,string,mod):
	mkey = gen_enc_key(key)
	nkey = gen_dec_key(mkey,mod)
	result = execute(nkey,string,mod)
	
	return result

# print the matrix
def print_matrix(matrix):
	if matrix==None:
		return None
	# get the biggest number
	big = len(str(len(alphabet)-1))+1	# biggest number + '-'
	tpl = "%%%dd " % big
	for i in range(len(matrix)):
		row = matrix[i]
		line = "| "
		for j in range(len(row)):
			line += tpl % row[j]
		line += "|"
		print(line)

def main(op,key,text,dry=False):
	mod = len(alphabet)

	# dry run is faster
	if dry:
		ekey = gen_enc_key(key)
		if op=='enc':
			print_matrix(ekey)
		else:	# op=='dec'
			dkey = gen_dec_key(ekey,mod)
			print_matrix(dkey)
		return
	
	# else just do it
	if op=='enc':
		res = encrypt(key,string,mod)
	else:
		res = decrypt(key,string,mod)
	
	print(res)

if __name__=='__main__':
	from sys import argv
	args = argv[1:]
	mhelp %= argv[0]
	if '--help' in args or len(args)<2:
		print(mhelp)
		exit(1)
	
	# parse arguments
	op = args[0]
	if op not in ['enc','dec']:
		print("error: unknown operation '%s'" % op)
		print(mhelp)
		exit(1)
	
	# moving forward
	args = args[1:]
	
	# possible indexes for the string
	indexes = range(len(args))
	
	dry = False
	key = None
	string = None

	for i in range(len(args)):
		p = args[i]
		# key
		if p[:2]=='-k':
			indexes[i] = -1
			if len(p)==2:
				key = args[i+1]
				i += 1
				indexes[i] = -1
			else:
				key = p[2:]
			continue
		elif p[:6]=='--key=':
			key = p[6:]
			indexes[i] = -1
			continue
		
		# alphabet
		if p[:2]=='-a':
			indexes[i] = -1
			if len(p)==2:
				alphabet = args[i+1]
				i += 1
				indexes[i] = -1
			else:
				alphabet = p[2:]
			__gen_rev()
			continue
		elif p[:11] == '--alphabet=':
			alphabet = p[11:]
			__gen_rev()
			continue
		
		# matrix
		if p == '-m' or p=='--matrix':
			indexes[i] = -1
			dry = True

	for i in range(len(indexes)):
		if indexes[i] != -1:
			string = args[indexes[i]]
			break
	
	if key==None:
		print("missing argument 'key'")
		exit(2)
	if string==None and not dry:
		print("missing the 'string'")
		exit(2)

	# else everything should be fine
	main(op,key,string,dry)
