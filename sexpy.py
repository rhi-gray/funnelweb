# -*- mode: python; -*-
__doc__ = """ Sexpy.
A module for parsing s-expressions.

Note that all functions automatically cast between #t/f <-> True/False

sread is the most important part of the module. It turns a flat string into a Python list containing "symbols" from the s-expression interpretation of that string. Note that it completely ignores comments, and as such, they will *not* be preserved if you, e.g., sread then swrite. To avoid this, we recommend using a (comment ...) node in your s-expressions to preserve such information.

swrite turns a Python list into a string containing the equivalent s-expression. Take note of the first parameter, which controls whether or not outer parentheses are printed.
write is a wrapper for swrite which will append to a file-like object.
"""

# The exported functions.
__all__ = ["sread", "swrite", "write"]

COMMENTS = [";"]
WHITESPACE = [" ", "\t", "\n"]
PARENS_OPEN = ["(", "{", "["]
PARENS_CLOSE = ["]", "}", ")"]
TRUTH = "#t"
FALSITY = "#f"

def sread(string, choffset = 0, tell_offset = False):
    """ Read a scheme expression, returning a list of symbols.
    Returns the list of symbols, and a character offset.
    """
    symbollist = []
    currentsymbol = ""
    IN_COMMENT = False
    skipcount = 0

    # Convert some things to Python.
    def typecast(k):
      if k == TRUTH: return True
      elif k == FALSITY: return False
      else: return k


    for i, ch in enumerate(string[choffset:]):
        if IN_COMMENT:
            if ch == "\n":
                IN_COMMENT = False
            else:
                continue
        elif skipcount > 0:
            skipcount -= 1
            continue

        # If it's an open parenthesis, recurse.
        elif ch in PARENS_OPEN:
            symbollist.append(currentsymbol) # Add the current symbol.
            value, offset = sread(string[i + 1:], tell_offset=True)
            symbollist.append(value) # Add the contents of the parens.
            skipcount += offset

            currentsymbol = ""

        # Close parens, return.
        elif ch in PARENS_CLOSE:
            symbollist.append(currentsymbol) # blahblah) is valid.
            # Strip empties and cast bools.
            symbollist = [typecast(k) for k in symbollist if k != ""]

            if tell_offset:
                return symbollist, i + 1 # The close-paren adds an extra character.
            else:
                return symbollist # Don't tell about the offset.

        # Comments should skip a line.
        elif ch in COMMENTS:
            symbollist.append(currentsymbol)
            currentsymbol = ""
            IN_COMMENT = True

        # Whitespace.
        elif ch in WHITESPACE:
            symbollist.append(currentsymbol)
            currentsymbol = ""

        # Otherwise, it's a symbol.
        else:
            currentsymbol += ch

    # Again, remove "" things and turn "#t"->True etc.
    symbollist = [typecast(k) for k in symbollist if k != ""]
    # Are we using this internally, basically.
    if tell_offset:
        return symbollist, 0 # Yes.
    else:
        return symbollist # Nope, the user doesn't need to know.

def swrite(expr, with_newlines = True, with_outer_parens = False):
  """ Return a string containing the s-expression equivalent of a particular list.
  """
  def cast(k):
    if isinstance(k, bool): return [FALSITY, TRUTH][k]
    else: return str(k)

  if not isinstance(expr, (list, tuple)):
    return cast(expr)
  elif not with_outer_parens:
    return " ".join([swrite(k, False, True) for k in expr])
  else:
    return "({body}){nl}".format(body=" ".join([swrite(k, True, True) for k in expr]),
                                 nl="\n" if with_newlines else "")

def write(lst, fobj):
  """ Write an s-expression to a file-like object.

  Write a Scheme-style s-expression to a file.
  Note that this assumes no outer-most layer of parens; e.g. if you call swrite([1, 2, 3], ...) your sexp file will contain "1\n2\n3". For "(1 2 3)", pass [[1, 2, 3]].
  """
  as_str = swrite(lst, True)
  fobj.write(as_str)
  fobj.write("\n")
