/* prdbg.c -- Print out generic debugging information.
   Copyright (C) 1995-2021 Free Software Foundation, Inc.
   Written by Ian Lance Taylor <ian@cygnus.com>.
   Tags style generation written by Salvador E. Tropea <set@computer.org>.

   This file is part of GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

/* This file prints out the generic debugging information, by
   supplying a set of routines to debug_write.  */

#include "sysdep.h"
#include <assert.h>
#include "bfd.h"
#include "libiberty.h"
#include "demangle.h"
#include "debug.h"
#include "budbg.h"

#define SHOULD_DUMP_STRUCTS 0
#define SHOULD_DUMP_VARIABLES 0
#define SHOULD_DUMP_FUNCTIONS 1
#define SHOULD_DUMP_FUNCARGS 0

/* This is the structure we use as a handle for these routines.  */

struct pr_handle
{
  /* File to print information to.  */
  FILE *f;
  /* Current indentation level.  */
  unsigned int indent;
  /* Type stack.  */
  struct pr_stack *stack;
  /* Parameter number we are about to output.  */
  int parameter;
};

/* The type stack.  */

struct pr_stack
{
  /* Next element on the stack.  */
  struct pr_stack *next;
  /* This element.  */
  char *type;
  /* Current visibility of fields if this is a class.  */
  enum debug_visibility visibility;
  /* Name of the current method we are handling.  */
  const char *method;
  /* Field number we are about to output.  */
  int field;
};

static void indent (struct pr_handle *);
static bool push_type (struct pr_handle *, const char *);
static bool prepend_type (struct pr_handle *, const char *);
static bool append_type (struct pr_handle *, const char *);
static bool substitute_type (struct pr_handle *, const char *);
static bool indent_type (struct pr_handle *);
static char *pop_type (struct pr_handle *);
static void print_vma (bfd_vma, char *, bool, bool);
static bool pr_fix_visibility (struct pr_handle *, enum debug_visibility);
static bool pr_start_compilation_unit (void *, const char *);
static bool pr_start_source (void *, const char *);
static bool pr_empty_type (void *);
static bool pr_void_type (void *);
static bool pr_int_type (void *, unsigned int, bool);
static bool pr_float_type (void *, unsigned int);
static bool pr_complex_type (void *, unsigned int);
static bool pr_bool_type (void *, unsigned int);
static bool pr_enum_type
  (void *, const char *, const char **, bfd_signed_vma *);
static bool pr_pointer_type (void *);
static bool pr_function_type (void *, int, bool);
static bool pr_reference_type (void *);
static bool pr_range_type (void *, bfd_signed_vma, bfd_signed_vma);
static bool pr_array_type (void *, bfd_signed_vma, bfd_signed_vma, bool);
static bool pr_set_type (void *, bool);
static bool pr_offset_type (void *);
static bool pr_method_type (void *, bool, int, bool);
static bool pr_const_type (void *);
static bool pr_volatile_type (void *);
static bool pr_start_struct_type
  (void *, const char *, unsigned int, bool, unsigned int);
static bool pr_struct_field
  (void *, const char *, bfd_vma, bfd_vma, enum debug_visibility);
static bool pr_end_struct_type (void *);
static bool pr_start_class_type
  (void *, const char *, unsigned int, bool, unsigned int, bool, bool);
static bool pr_class_static_member
  (void *, const char *, const char *, enum debug_visibility);
static bool pr_class_baseclass
  (void *, bfd_vma, bool, enum debug_visibility);
static bool pr_class_start_method (void *, const char *);
static bool pr_class_method_variant
  (void *, const char *, enum debug_visibility, bool, bool, bfd_vma, bool);
static bool pr_class_static_method_variant
  (void *, const char *, enum debug_visibility, bool, bool);
static bool pr_class_end_method (void *);
static bool pr_end_class_type (void *);
static bool pr_typedef_type (void *, const char *);
static bool pr_tag_type
  (void *, const char *, unsigned int, enum debug_type_kind);
static bool pr_typdef (void *, const char *);
static bool pr_tag (void *, const char *);
static bool pr_int_constant (void *, const char *, bfd_vma);
static bool pr_float_constant (void *, const char *, double);
static bool pr_typed_constant (void *, const char *, bfd_vma);
static bool pr_variable (void *, const char *, enum debug_var_kind, bfd_vma);
static bool pr_start_function (void *, const char *, bool);
static bool pr_function_parameter
  (void *, const char *, enum debug_parm_kind, bfd_vma);
static bool pr_start_block (void *, bfd_vma);
static bool pr_end_block (void *, bfd_vma);
static bool pr_end_function (void *);
static bool pr_lineno (void *, const char *, unsigned long, bfd_vma);

static const struct debug_write_fns pr_fns =
{
  pr_start_compilation_unit,
  pr_start_source,
  pr_empty_type,
  pr_void_type,
  pr_int_type,
  pr_float_type,
  pr_complex_type,
  pr_bool_type,
  pr_enum_type,
  pr_pointer_type,
  pr_function_type,
  pr_reference_type,
  pr_range_type,
  pr_array_type,
  pr_set_type,
  pr_offset_type,
  pr_method_type,
  pr_const_type,
  pr_volatile_type,
  pr_start_struct_type,
  pr_struct_field,
  pr_end_struct_type,
  pr_start_class_type,
  pr_class_static_member,
  pr_class_baseclass,
  pr_class_start_method,
  pr_class_method_variant,
  pr_class_static_method_variant,
  pr_class_end_method,
  pr_end_class_type,
  pr_typedef_type,
  pr_tag_type,
  pr_typdef,
  pr_tag,
  pr_int_constant,
  pr_float_constant,
  pr_typed_constant,
  pr_variable,
  pr_start_function,
  pr_function_parameter,
  pr_start_block,
  pr_end_block,
  pr_end_function,
  pr_lineno
};


/* Print out the generic debugging information recorded in dhandle.  */

bool
print_debugging_info (FILE *f, void *dhandle, bfd *abfd, asymbol **syms,
		      char * (*demangler) (struct bfd *, const char *, int),
		      bool as_tags)
{
  struct pr_handle info;
  (void)abfd;
  (void)syms;
  (void)demangler;
  (void)as_tags;

  info.f = f;
  info.indent = 0;
  info.stack = NULL;
  info.parameter = 0;

  return debug_write (dhandle, &pr_fns, (void *) & info);
}

/* Indent to the current indentation level.  */

static void
indent (struct pr_handle *info)
{
  unsigned int i;

  for (i = 0; i < info->indent; i++)
    putc (' ', info->f);
}

/* Push a type on the type stack.  */

static bool
push_type (struct pr_handle *info, const char *type)
{
  struct pr_stack *n;

  if (type == NULL)
    return false;

  n = (struct pr_stack *) xmalloc (sizeof *n);
  memset (n, 0, sizeof *n);

  n->type = xstrdup (type);
  n->visibility = DEBUG_VISIBILITY_IGNORE;
  n->method = NULL;
  n->next = info->stack;
  info->stack = n;

  return true;
}

/* Prepend a string onto the type on the top of the type stack.  */

static bool
prepend_type (struct pr_handle *info, const char *s)
{
  char *n;

  assert (info->stack != NULL);

  n = (char *) xmalloc (strlen (s) + strlen (info->stack->type) + 1);
  sprintf (n, "%s%s", s, info->stack->type);
  free (info->stack->type);
  info->stack->type = n;

  return true;
}

/* Append a string to the type on the top of the type stack.  */

static bool
append_type (struct pr_handle *info, const char *s)
{
  unsigned int len;

  if (s == NULL)
    return false;

  assert (info->stack != NULL);

  len = strlen (info->stack->type);
  info->stack->type = (char *) xrealloc (info->stack->type,
					 len + strlen (s) + 1);
  strcpy (info->stack->type + len, s);

  return true;
}

/* We use an underscore to indicate where the name should go in a type
   string.  This function substitutes a string for the underscore.  If
   there is no underscore, the name follows the type.  */

static bool
substitute_type (struct pr_handle *info, const char *s)
{
  char *u;

  assert (info->stack != NULL);

  u = strchr (info->stack->type, '|');
  if (u != NULL)
    {
      char *n;

      n = (char *) xmalloc (strlen (info->stack->type) + strlen (s));

      memcpy (n, info->stack->type, u - info->stack->type);
      strcpy (n + (u - info->stack->type), s);
      strcat (n, u + 1);

      free (info->stack->type);
      info->stack->type = n;

      return true;
    }

  u = strchr (s, '|');
  if (u != NULL)
    {
      char *n;

      n = (char *) xmalloc (strlen (info->stack->type) + strlen (s));

      memcpy (n, s, u - s);
      strcpy (n + (u - s), info->stack->type);
      strcat (n, u + 1);

      free (info->stack->type);
      info->stack->type = n;

      return true;
    }

#if 0
  if (strchr (s, '|') != NULL
      && (strchr (info->stack->type, '{') != NULL
	  || strchr (info->stack->type, '(') != NULL))
    {
      if (! prepend_type (info, "(")
	  || ! append_type (info, ")"))
	return false;
    }
#endif

  if (*s == '\0')
    return true;

  return (append_type (info, " ")
	  && append_type (info, s));
}

/* Indent the type at the top of the stack by appending spaces.  */

static bool
indent_type (struct pr_handle *info)
{
  unsigned int i;

  for (i = 0; i < info->indent; i++)
    {
      if (! append_type (info, " "))
	return false;
    }

  return true;
}

/* Pop a type from the type stack.  */

static char *
pop_type (struct pr_handle *info)
{
  struct pr_stack *o;
  char *ret;

  assert (info->stack != NULL);

  o = info->stack;
  info->stack = o->next;
  ret = o->type;
  free (o);

  return ret;
}

/* Print a VMA value into a string.  */

static void
print_vma (bfd_vma vma, char *buf, bool unsignedp, bool hexp)
{
  if (sizeof (vma) <= sizeof (unsigned long))
    {
#if 0
      if (hexp)
	sprintf (buf, "0x%lx", (unsigned long) vma);
      else if (unsignedp)
	sprintf (buf, "%lu", (unsigned long) vma);
      else
	sprintf (buf, "%ld", (long) vma);
#endif
      if (unsignedp)
        sprintf (buf, "%lu", (unsigned long) vma);
      else
        sprintf (buf, "%ld", (long) vma);
    }
#if BFD_HOST_64BIT_LONG_LONG
  else if (sizeof (vma) <= sizeof (unsigned long long))
    {
#if 0
#ifndef __MSVCRT__
      if (hexp)
	sprintf (buf, "0x%llx", (unsigned long long) vma);
      else if (unsignedp)
	sprintf (buf, "%llu", (unsigned long long) vma);
      else
	sprintf (buf, "%lld", (long long) vma);
#else
      if (hexp)
	sprintf (buf, "0x%I64x", (unsigned long long) vma);
      else if (unsignedp)
	sprintf (buf, "%I64u", (unsigned long long) vma);
      else
	sprintf (buf, "%I64d", (long long) vma);
#endif
#endif
      if (unsignedp)
        sprintf (buf, "%I64u", (unsigned long long) vma);
      else
        sprintf (buf, "%I64d", (long long) vma);
    }
#endif
  else
    {
      buf[0] = '0';
      buf[1] = 'x';
      sprintf_vma (buf + 2, vma);
    }
}

/* Start a new compilation unit.  */

static bool
pr_start_compilation_unit (void *p, const char *filename)
{
  struct pr_handle *info = (struct pr_handle *) p;

  assert (info->indent == 0);

#if 0
  fprintf (info->f, "%s:\n", filename);
#else
  fprintf (info->f, "{\"info_type\" : \"start_compilation_unit\", \"filename\" : \"%s\"},\n", filename);
#endif

  return true;
}

/* Start a source file within a compilation unit.  */

static bool
pr_start_source (void *p, const char *filename)
{
  struct pr_handle *info = (struct pr_handle *) p;

  assert (info->indent == 0);

#if 0
  fprintf (info->f, " %s:\n", filename);
#else
  fprintf (info->f, "{\"info_type\" : \"start_source\", \"filename\" : \"%s\"},\n", filename);
#endif

  return true;
}

/* Push an empty type onto the type stack.  */

static bool
pr_empty_type (void *p)
{
  struct pr_handle *info = (struct pr_handle *) p;

  return push_type (info, "<undefined>");
}

/* Push a void type onto the type stack.  */

static bool
pr_void_type (void *p)
{
  struct pr_handle *info = (struct pr_handle *) p;

#if 0
  return push_type (info, "void");
#endif
  return push_type (info, "{\"info_type\" : \"void_type\"}");
}

/* Push an integer type onto the type stack.  */

static bool
pr_int_type (void *p, unsigned int size, bool unsignedp)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char ab[200];

#if 0
  sprintf (ab, "%sint%d", unsignedp ? "u" : "", size * 8);
#endif
  sprintf (ab, "{\"info_type\" : \"int_type\", \"unsigned\" : %s, \"size\" : %d}", unsignedp ? "true" : "false", size * 8);
  return push_type (info, ab);
}

/* Push a floating type onto the type stack.  */

static bool
pr_float_type (void *p, unsigned int size)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char ab[100];

#if 0
  if (size == 4)
    return push_type (info, "float");
  else if (size == 8)
    return push_type (info, "double");
#endif

#if 0
  sprintf (ab, "float%d", size * 8);
#endif
  sprintf (ab, "{\"info_type\" : \"float_type\", \"size\" : %d}", size * 8);
  return push_type (info, ab);
}

/* Push a complex type onto the type stack.  */

static bool
pr_complex_type (void *p, unsigned int size)
{
  struct pr_handle *info = (struct pr_handle *) p;

  if (! pr_float_type (p, size))
    return false;

#if 0
  return prepend_type (info, "complex ");
#endif
  return prepend_type (info, "{\"info_type\" : \"complex_type\", \"type\" : ") && append_type (info, "}");
}

/* Push a bool type onto the type stack.  */

static bool
pr_bool_type (void *p, unsigned int size)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char ab[100];

#if 0
  sprintf (ab, "bool%d", size * 8);

  return push_type (info, ab);
#endif
  sprintf (ab, "{\"info_type\" : \"bool_type\", \"size\" : %d}", size * 8);
  return push_type (info, ab);
}

/* Push an enum type onto the type stack.  */

static bool
pr_enum_type (void *p, const char *tag, const char **names,
	      bfd_signed_vma *values)
{
  struct pr_handle *info = (struct pr_handle *) p;
  unsigned int i;
#if 0
  bfd_signed_vma val;
#endif

#if 0
  if (! push_type (info, "enum "))
    return false;
  if (tag != NULL)
    {
      if (! append_type (info, tag)
	  || ! append_type (info, " "))
	return false;
    }
  if (! append_type (info, "{ "))
    return false;

  if (names == NULL)
    {
      if (! append_type (info, "/* undefined */"))
	return false;
    }
  else
    {
      val = 0;
      for (i = 0; names[i] != NULL; i++)
	{
	  if (i > 0)
	    {
	      if (! append_type (info, ", "))
		return false;
	    }

	  if (! append_type (info, names[i]))
	    return false;

	  if (values[i] != val)
	    {
	      char ab[22];

	      print_vma (values[i], ab, false, false);
	      if (! append_type (info, " = ")
		  || ! append_type (info, ab))
		return false;
	      val = values[i];
	    }

	  ++val;
	}
    }

  return append_type (info, " }");
#endif
  if (! push_type (info, "{\"info_type\" : \"enum_type\", "))
    return false;
  if (tag != NULL)
  {
    if (! append_type (info, "\"tag\" : \""))
      return false;
    if (! append_type (info, tag))
      return false;
    if (! append_type (info, "\", "))
      return false;
  }

  if (names != NULL)
  {
    if (! append_type (info, "\"names\" : ["))
      return false;
    for (i = 0; names[i] != NULL; i++)
    {
      if (i > 0)
      {
        if (! append_type (info, ", "))
          return false;
      }
      if (! append_type (info, "[\""))
        return false;
      if (! append_type (info, names[i]))
        return false;
      if (! append_type (info, "\", "))
        return false;
      char ab[22];

      print_vma (values[i], ab, false, false);
      if (! append_type (info, ab))
        return false;
      if (! append_type (info, "]"))
        return false;
    }
    if (! append_type (info, "]"))
      return false;
  }
  if (! append_type (info, "}"))
    return false;
  return true;
}

/* Turn the top type on the stack into a pointer.  */

static bool
pr_pointer_type (void *p)
{
  struct pr_handle *info = (struct pr_handle *) p;
#if 0
  char *s;
#endif

  assert (info->stack != NULL);

#if 0
  s = strchr (info->stack->type, '|');
  if (s != NULL && s[1] == '[')
    return substitute_type (info, "(*|)");
  return substitute_type (info, "*|");
#endif

  return substitute_type (info, "{\"info_type\" : \"pointer_type\", \"type\" : |}");
}

/* Turn the top type on the stack into a function returning that type.  */

static bool
pr_function_type (void *p, int argcount, bool varargs)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char **arg_types;
  unsigned int len;
  char *s;

  assert (info->stack != NULL);

  len = 10;

#if 0
  if (argcount <= 0)
    {
      arg_types = NULL;
      len += 15;
    }
  else
    {
      int i;

      arg_types = (char **) xmalloc (argcount * sizeof *arg_types);
      for (i = argcount - 1; i >= 0; i--)
	{
	  if (! substitute_type (info, ""))
	    {
	      free (arg_types);
	      return false;
	    }
	  arg_types[i] = pop_type (info);
	  if (arg_types[i] == NULL)
	    {
	      free (arg_types);
	      return false;
	    }
	  len += strlen (arg_types[i]) + 2;
	}
      if (varargs)
	len += 5;
    }

  /* Now the return type is on the top of the stack.  */

  s = (char *) xmalloc (len);
  strcpy (s, "(|) (");

  if (argcount < 0)
    strcat (s, "/* unknown */");
  else
    {
      int i;

      for (i = 0; i < argcount; i++)
	{
	  if (i > 0)
	    strcat (s, ", ");
	  strcat (s, arg_types[i]);
	}
      if (varargs)
	{
	  if (i > 0)
	    strcat (s, ", ");
	  strcat (s, "...");
	}
      if (argcount > 0)
	free (arg_types);
    }

  strcat (s, ")");

  if (! substitute_type (info, s))
    return false;

  free (s);
#endif
  if (argcount <= 0)
  {
    arg_types = NULL;
    len += 15;
  }
  else
  {
    int i;

    arg_types = (char **) xmalloc (argcount * sizeof *arg_types);
    for (i = argcount - 1; i >= 0; i--)
    {
      if (! substitute_type (info, "null"))
      {
        free (arg_types);
        return false;
      }
      arg_types[i] = pop_type (info);
      if (arg_types[i] == NULL)
      {
        free (arg_types);
        return false;
      }
      len += strlen (arg_types[i]) + 2;
    }
    if (varargs)
      len += 5;
  }

  /* Now the return type is on the top of the stack.  */

  if (! push_type (info, "{\"info_type\" : \"function_type\""))
    return false;

  if (argcount >= 0)
  {

    if (! append_type (info, ", \"arguments\" : ["))
      return false;
    int i;
    if (argcount > 0)
    {
      for (i = 0; i < argcount; i++)
      {
        if (i > 0)
          if (! append_type (info, ","))
            return false;
        if (! append_type (info, arg_types[i]))
          return false;
      }
    }
    if (! append_type (info, "]"))
      return false;
    if (argcount > 0)
      free (arg_types);
  }
  if (! append_type (info, ", \"varargs\" : "))
    return false;
  if (! append_type (info, varargs ? "true" : "false"))
    return false;
  if (! append_type (info, ", \"type\" : |}"))
    return false;

  s = pop_type (info);
  if (s == NULL)
    return false;

  if (! substitute_type (info, s))
    return false;
  return true;
}

/* Turn the top type on the stack into a reference to that type.  */

static bool
pr_reference_type (void *p)
{
  struct pr_handle *info = (struct pr_handle *) p;

  assert (info->stack != NULL);

  return substitute_type (info, "&|");
}

/* Make a range type.  */

static bool
pr_range_type (void *p, bfd_signed_vma lower, bfd_signed_vma upper)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char abl[22], abu[22];

  assert (info->stack != NULL);

  if (! substitute_type (info, ""))
    return false;

  print_vma (lower, abl, false, false);
  print_vma (upper, abu, false, false);

  return (prepend_type (info, "range (")
	  && append_type (info, "):")
	  && append_type (info, abl)
	  && append_type (info, ":")
	  && append_type (info, abu));
}

/* Make an array type.  */

static bool
pr_array_type (void *p, bfd_signed_vma lower, bfd_signed_vma upper,
	       bool stringp)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *range_type;
  char abl[22], abu[22], ab[200], abb[400];

  range_type = pop_type (info);
  if (range_type == NULL)
    return false;

#if 0
  if (lower == 0)
    {
      if (upper == -1)
	sprintf (ab, "|[]");
      else
	{
	  print_vma (upper + 1, abu, false, false);
	  sprintf (ab, "|[%s]", abu);
	}
    }
  else
    {
      print_vma (lower, abl, false, false);
      print_vma (upper, abu, false, false);
      sprintf (ab, "|[%s:%s]", abl, abu);
    }
#endif
#if 0
  if (lower == 0)
    {
      if (upper == -1)
  sprintf (ab, "\"varlength\" : true");
      else
  {
    print_vma (upper + 1, abu, false, false);
    sprintf (ab, "\"length\" : %s", abu);
  }
    }
  else
#endif
    {
      print_vma (lower, abl, false, false);
      print_vma (upper, abu, false, false);
      sprintf (ab, "\"lower\" : %s, \"upper\" : %s", abl, abu);
    }

#if 0
  if (! substitute_type (info, ab))
    return false;

  if (strcmp (range_type, "int") != 0)
    {
      if (! append_type (info, ":")
	  || ! append_type (info, range_type))
	return false;
    }

  if (stringp)
    {
      if (! append_type (info, " /* string */"))
	return false;
    }
#endif

  sprintf (abb, "{\"info_type\" : \"array_type\", %s, \"type\" : |, \"stringp\" : %s, \"range_type\" : %s}", ab, stringp ? "true" : "false", range_type);
  if (! substitute_type (info, abb))
    return false;

#if 0
  if (! push_type (info, "{\"info_type\" : \"array_type\", "))
    return false;
  if (! append_type (info, ab))
    return false;
  sprintf (ab, ", \"kind\" : |, \"stringp\" : %s, \"range_type\" : %s", stringp ? "true" : "false", range_type);
  if (! append_type (info, ab))
    return false;

  if (! append_type (info, "}"))
    return false;
#endif

  return true;
}

/* Make a set type.  */

static bool
pr_set_type (void *p, bool bitstringp)
{
  struct pr_handle *info = (struct pr_handle *) p;

  if (! substitute_type (info, ""))
    return false;

  if (! prepend_type (info, "set { ")
      || ! append_type (info, " }"))
    return false;

  if (bitstringp)
    {
      if (! append_type (info, "/* bitstring */"))
	return false;
    }

  return true;
}

/* Make an offset type.  */

static bool
pr_offset_type (void *p)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *t;

  if (! substitute_type (info, ""))
    return false;

  t = pop_type (info);
  if (t == NULL)
    return false;

  return (substitute_type (info, "")
	  && prepend_type (info, " ")
	  && prepend_type (info, t)
	  && append_type (info, "::|"));
}

/* Make a method type.  */

static bool
pr_method_type (void *p, bool domain, int argcount, bool varargs)
{
  struct pr_handle *info = (struct pr_handle *) p;
  unsigned int len;
  char *domain_type;
  char **arg_types;
  char *s;

  len = 10;

  if (! domain)
    domain_type = NULL;
  else
    {
      if (! substitute_type (info, ""))
	return false;
      domain_type = pop_type (info);
      if (domain_type == NULL)
	return false;
      if (startswith (domain_type, "class ")
	  && strchr (domain_type + sizeof "class " - 1, ' ') == NULL)
	domain_type += sizeof "class " - 1;
      else if (startswith (domain_type, "union class ")
	       && (strchr (domain_type + sizeof "union class " - 1, ' ')
		   == NULL))
	domain_type += sizeof "union class " - 1;
      len += strlen (domain_type);
    }

  if (argcount <= 0)
    {
      arg_types = NULL;
      len += 15;
    }
  else
    {
      int i;

      arg_types = (char **) xmalloc (argcount * sizeof *arg_types);
      for (i = argcount - 1; i >= 0; i--)
	{
	  if (! substitute_type (info, ""))
	    {
	      free (arg_types);
	      return false;
	    }
	  arg_types[i] = pop_type (info);
	  if (arg_types[i] == NULL)
	    {
	      free (arg_types);
	      return false;
	    }
	  len += strlen (arg_types[i]) + 2;
	}
      if (varargs)
	len += 5;
    }

  /* Now the return type is on the top of the stack.  */

  s = (char *) xmalloc (len);
  if (! domain)
    *s = '\0';
  else
    strcpy (s, domain_type);
  strcat (s, "::| (");

  if (argcount < 0)
    strcat (s, "/* unknown */");
  else
    {
      int i;

      for (i = 0; i < argcount; i++)
	{
	  if (i > 0)
	    strcat (s, ", ");
	  strcat (s, arg_types[i]);
	}
      if (varargs)
	{
	  if (i > 0)
	    strcat (s, ", ");
	  strcat (s, "...");
	}
      if (argcount > 0)
	free (arg_types);
    }

  strcat (s, ")");

  if (! substitute_type (info, s))
    return false;

  free (s);

  return true;
}

/* Make a const qualified type.  */

static bool
pr_const_type (void *p)
{
  struct pr_handle *info = (struct pr_handle *) p;

  return substitute_type (info, "{\"info_type\" : \"const_type\", \"type\" : |}");
}

/* Make a volatile qualified type.  */

static bool
pr_volatile_type (void *p)
{
  struct pr_handle *info = (struct pr_handle *) p;

  return substitute_type (info, "{\"info_type\" : \"volatile_type\", \"type\" : |}");
}

/* Start accumulating a struct type.  */

static bool
pr_start_struct_type (void *p, const char *tag, unsigned int id,
		      bool structp, unsigned int size)
{
  struct pr_handle *info = (struct pr_handle *) p;

#if 0
#if SHOULD_DUMP_STRUCTS
  info->indent += 2;
#endif
#endif

#if 0
  if (! push_type (info, structp ? "struct " : "union "))
    return false;
  if (tag != NULL)
    {
      if (! append_type (info, tag))
	return false;
    }
  else
    {
      char idbuf[20];

      sprintf (idbuf, "__anon_struct_%u", id);
      if (! append_type (info, idbuf))
	return false;
    }
#endif

  if (! push_type (info, "{\"info_type\" : \"start_struct_type\""))
    return false;
  if (tag != NULL)
  {
    if (! append_type (info, ", \"tag\" : \""))
      return false;
    if (! append_type (info, tag))
      return false;
    if (! append_type (info, "\""))
      return false;
  }
  if (! append_type (info, ", \"id\" : "))
    return false;
  char idbuf[20];

  sprintf (idbuf, "%u", id);
  if (! append_type (info, idbuf))
    return false;
  if (! append_type (info, ", \"size\" : "))
    return false;
  sprintf (idbuf, "%u", size);
  if (! append_type (info, idbuf))
    return false;
  if (! append_type (info, ", \"structp\" : "))
    return false;
  if (! append_type (info, structp ? "true" : "false"))
    return false;
  if (! append_type (info, ", \"fields\" : ["))
    return false;
#if 0
#if SHOULD_DUMP_STRUCTS
  if (! append_type (info, " {"))
    return false;
  if (size != 0 || tag != NULL)
    {
      char ab[30];

      if (! append_type (info, " /*"))
	return false;

      if (size != 0)
	{
	  sprintf (ab, " size %u", size);
	  if (! append_type (info, ab))
	    return false;
	}
      if (tag != NULL)
	{
	  sprintf (ab, " id %u", id);
	  if (! append_type (info, ab))
	    return false;
	}
      if (! append_type (info, " */"))
	return false;
    }
  if (! append_type (info, "\n"))
    return false;
#endif
#endif

  info->stack->visibility = DEBUG_VISIBILITY_PUBLIC;
  info->stack->field = 1;

#if 0
#if SHOULD_DUMP_STRUCTS
  return indent_type (info);
#else
  return true;
#endif
#endif
  return true;
}

/* Output the visibility of a field in a struct.  */

static bool
pr_fix_visibility (struct pr_handle *info, enum debug_visibility visibility)
{
  const char *s = NULL;
  char *t;
  unsigned int len;

  assert (info->stack != NULL);

  if (info->stack->visibility == visibility)
    return true;

  switch (visibility)
    {
    case DEBUG_VISIBILITY_PUBLIC:
      s = "public";
      break;
    case DEBUG_VISIBILITY_PRIVATE:
      s = "private";
      break;
    case DEBUG_VISIBILITY_PROTECTED:
      s = "protected";
      break;
    case DEBUG_VISIBILITY_IGNORE:
      s = "/* ignore */";
      break;
    default:
      abort ();
      return false;
    }

  /* Trim off a trailing space in the struct string, to make the
     output look a bit better, then stick on the visibility string.  */

  t = info->stack->type;
  len = strlen (t);
  assert (t[len - 1] == ' ');
  t[len - 1] = '\0';

  if (! append_type (info, s)
      || ! append_type (info, ":\n")
      || ! indent_type (info))
    return false;

  info->stack->visibility = visibility;

  return true;
}

/* Add a field to a struct type.  */

static bool
pr_struct_field (void *p, const char *name, bfd_vma bitpos, bfd_vma bitsize,
		 enum debug_visibility visibility)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char ab[22];
  char *t;
  (void)visibility;

#if 0
#if SHOULD_DUMP_STRUCTS
  if (! substitute_type (info, name))
    return false;

  if (! append_type (info, "; /* "))
    return false;

  if (bitsize != 0)
    {
      print_vma (bitsize, ab, true, false);
      if (! append_type (info, "bitsize ")
	  || ! append_type (info, ab)
	  || ! append_type (info, ", "))
	return false;
    }

  print_vma (bitpos, ab, true, false);
  if (! append_type (info, "bitpos ")
      || ! append_type (info, ab)
      || ! append_type (info, " */\n")
      || ! indent_type (info))
    return false;
#endif
#endif
#if 1
  t = pop_type (info);
  if (t == NULL)
    return false;
#endif
  if (info->stack->field != 1)
  {
    if (! append_type (info, ", "))
      return false;
  }
  info->stack->field += 1;
  if (! append_type (info, "{\"info_type\" : \"struct_field\""))
    return false;
#if 1
  if (! append_type (info, ", \"type\" : "))
    return false;
  if (! append_type (info, t))
    return false;
#endif
  if (! append_type (info, ", \"name\" : \""))
    return false;
  if (! append_type (info, name))
    return false;
  print_vma (bitsize, ab, true, false);
  if (! append_type (info, "\""))
    return false;
  if (! append_type (info, ", \"bitsize\" : "))
    return false;
  if (! append_type (info, ab))
    return false;
  print_vma (bitpos, ab, true, false);
  if (! append_type (info, ", \"bitpos\" : "))
    return false;
  if (! append_type (info, ab))
    return false;

  if (! append_type (info, "}"))
    return false;
#if 0
#if SHOULD_DUMP_STRUCTS
  if (! pr_fix_visibility (info, visibility))
    return false;

  return append_type (info, t);
#else
  return true;
#endif
#endif
  return true;
}

/* Finish a struct type.  */

static bool
pr_end_struct_type (void *p)
{
  struct pr_handle *info = (struct pr_handle *) p;
#if 0
  char *s;
#endif

#if 0
#if SHOULD_DUMP_STRUCTS
  assert (info->stack != NULL);
  assert (info->indent >= 2);

  info->indent -= 2;

  /* Change the trailing indentation to have a close brace.  */
  s = info->stack->type + strlen (info->stack->type) - 2;
  assert (s[0] == ' ' && s[1] == ' ' && s[2] == '\0');

  *s++ = '}';
  *s = '\0';
#endif
#endif
  if (! append_type (info, "]}"))
    return false;

  return true;
}

/* Start a class type.  */

static bool
pr_start_class_type (void *p, const char *tag, unsigned int id,
		     bool structp, unsigned int size,
		     bool vptr, bool ownvptr)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *tv = NULL;

  info->indent += 2;

  if (vptr && ! ownvptr)
    {
      tv = pop_type (info);
      if (tv == NULL)
	return false;
    }

  if (! push_type (info, structp ? "class " : "union class "))
    return false;
  if (tag != NULL)
    {
      if (! append_type (info, tag))
	return false;
    }
  else
    {
      char idbuf[20];

      sprintf (idbuf, "__anon_struct_%u", id);
      if (! append_type (info, idbuf))
	return false;
    }

  if (! append_type (info, " {"))
    return false;
  if (size != 0 || vptr || ownvptr || tag != NULL)
    {
      if (! append_type (info, " /*"))
	return false;

      if (size != 0)
	{
	  char ab[20];

	  sprintf (ab, "%u", size);
	  if (! append_type (info, " size ")
	      || ! append_type (info, ab))
	    return false;
	}

      if (vptr)
	{
	  if (! append_type (info, " vtable "))
	    return false;
	  if (ownvptr)
	    {
	      if (! append_type (info, "self "))
		return false;
	    }
	  else
	    {
	      if (! append_type (info, tv)
		  || ! append_type (info, " "))
		return false;
	    }
	}

      if (tag != NULL)
	{
	  char ab[30];

	  sprintf (ab, " id %u", id);
	  if (! append_type (info, ab))
	    return false;
	}

      if (! append_type (info, " */"))
	return false;
    }

  info->stack->visibility = DEBUG_VISIBILITY_PRIVATE;

  return (append_type (info, "\n")
	  && indent_type (info));
}

/* Add a static member to a class.  */

static bool
pr_class_static_member (void *p, const char *name, const char *physname,
			enum debug_visibility visibility)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *t;

  if (! substitute_type (info, name))
    return false;

  if (! prepend_type (info, "static ")
      || ! append_type (info, "; /* ")
      || ! append_type (info, physname)
      || ! append_type (info, " */\n")
      || ! indent_type (info))
    return false;

  t = pop_type (info);
  if (t == NULL)
    return false;

  if (! pr_fix_visibility (info, visibility))
    return false;

  return append_type (info, t);
}

/* Add a base class to a class.  */

static bool
pr_class_baseclass (void *p, bfd_vma bitpos, bool is_virtual,
		    enum debug_visibility visibility)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *t;
  const char *prefix;
  char ab[22];
  char *s, *l, *n;

  assert (info->stack != NULL && info->stack->next != NULL);

  if (! substitute_type (info, ""))
    return false;

  t = pop_type (info);
  if (t == NULL)
    return false;

  if (startswith (t, "class "))
    t += sizeof "class " - 1;

  /* Push it back on to take advantage of the prepend_type and
     append_type routines.  */
  if (! push_type (info, t))
    return false;

  if (is_virtual)
    {
      if (! prepend_type (info, "virtual "))
	return false;
    }

  switch (visibility)
    {
    case DEBUG_VISIBILITY_PUBLIC:
      prefix = "public ";
      break;
    case DEBUG_VISIBILITY_PROTECTED:
      prefix = "protected ";
      break;
    case DEBUG_VISIBILITY_PRIVATE:
      prefix = "private ";
      break;
    default:
      prefix = "/* unknown visibility */ ";
      break;
    }

  if (! prepend_type (info, prefix))
    return false;

  if (bitpos != 0)
    {
      print_vma (bitpos, ab, true, false);
      if (! append_type (info, " /* bitpos ")
	  || ! append_type (info, ab)
	  || ! append_type (info, " */"))
	return false;
    }

  /* Now the top of the stack is something like "public A / * bitpos
     10 * /".  The next element on the stack is something like "class
     xx { / * size 8 * /\n...".  We want to substitute the top of the
     stack in before the {.  */
  s = strchr (info->stack->next->type, '{');
  assert (s != NULL);
  --s;

  /* If there is already a ':', then we already have a baseclass, and
     we must append this one after a comma.  */
  for (l = info->stack->next->type; l != s; l++)
    if (*l == ':')
      break;
  if (! prepend_type (info, l == s ? " : " : ", "))
    return false;

  t = pop_type (info);
  if (t == NULL)
    return false;

  n = (char *) xmalloc (strlen (info->stack->type) + strlen (t) + 1);
  memcpy (n, info->stack->type, s - info->stack->type);
  strcpy (n + (s - info->stack->type), t);
  strcat (n, s);

  free (info->stack->type);
  info->stack->type = n;

  free (t);

  return true;
}

/* Start adding a method to a class.  */

static bool
pr_class_start_method (void *p, const char *name)
{
  struct pr_handle *info = (struct pr_handle *) p;

  assert (info->stack != NULL);
  info->stack->method = name;
  return true;
}

/* Add a variant to a method.  */

static bool
pr_class_method_variant (void *p, const char *physname,
			 enum debug_visibility visibility,
			 bool constp, bool volatilep,
			 bfd_vma voffset, bool context)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *method_type;
  char *context_type;

  assert (info->stack != NULL);
  assert (info->stack->next != NULL);

  /* Put the const and volatile qualifiers on the type.  */
  if (volatilep)
    {
      if (! append_type (info, " volatile"))
	return false;
    }
  if (constp)
    {
      if (! append_type (info, " const"))
	return false;
    }

  /* Stick the name of the method into its type.  */
  if (! substitute_type (info,
			 (context
			  ? info->stack->next->next->method
			  : info->stack->next->method)))
    return false;

  /* Get the type.  */
  method_type = pop_type (info);
  if (method_type == NULL)
    return false;

  /* Pull off the context type if there is one.  */
  if (! context)
    context_type = NULL;
  else
    {
      context_type = pop_type (info);
      if (context_type == NULL)
	return false;
    }

  /* Now the top of the stack is the class.  */

  if (! pr_fix_visibility (info, visibility))
    return false;

  if (! append_type (info, method_type)
      || ! append_type (info, " /* ")
      || ! append_type (info, physname)
      || ! append_type (info, " "))
    return false;
  if (context || voffset != 0)
    {
      char ab[22];

      if (context)
	{
	  if (! append_type (info, "context ")
	      || ! append_type (info, context_type)
	      || ! append_type (info, " "))
	    return false;
	}
      print_vma (voffset, ab, true, false);
      if (! append_type (info, "voffset ")
	  || ! append_type (info, ab))
	return false;
    }

  return (append_type (info, " */;\n")
	  && indent_type (info));
}

/* Add a static variant to a method.  */

static bool
pr_class_static_method_variant (void *p, const char *physname,
				enum debug_visibility visibility,
				bool constp, bool volatilep)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *method_type;

  assert (info->stack != NULL);
  assert (info->stack->next != NULL);
  assert (info->stack->next->method != NULL);

  /* Put the const and volatile qualifiers on the type.  */
  if (volatilep)
    {
      if (! append_type (info, " volatile"))
	return false;
    }
  if (constp)
    {
      if (! append_type (info, " const"))
	return false;
    }

  /* Mark it as static.  */
  if (! prepend_type (info, "static "))
    return false;

  /* Stick the name of the method into its type.  */
  if (! substitute_type (info, info->stack->next->method))
    return false;

  /* Get the type.  */
  method_type = pop_type (info);
  if (method_type == NULL)
    return false;

  /* Now the top of the stack is the class.  */

  if (! pr_fix_visibility (info, visibility))
    return false;

  return (append_type (info, method_type)
	  && append_type (info, " /* ")
	  && append_type (info, physname)
	  && append_type (info, " */;\n")
	  && indent_type (info));
}

/* Finish up a method.  */

static bool
pr_class_end_method (void *p)
{
  struct pr_handle *info = (struct pr_handle *) p;

  info->stack->method = NULL;
  return true;
}

/* Finish up a class.  */

static bool
pr_end_class_type (void *p)
{
  return pr_end_struct_type (p);
}

/* Push a type on the stack using a typedef name.  */

static bool
pr_typedef_type (void *p, const char *name)
{
  struct pr_handle *info = (struct pr_handle *) p;
#if 1
  if (! push_type (info, "{\"info_type\" : \"typedef_type\""))
    return false;

  if (! append_type (info, ", \"name\" : \""))
    return false;
  if (! append_type (info, name))
    return false;
  if (! append_type (info, "\""))
    return false;

  if (! append_type (info, "}"))
    return false;
#endif

#if 1
  return true;
#endif
#if 0
  return push_type (info, name);
#endif
}

/* Push a type on the stack using a tag name.  */

static bool
pr_tag_type (void *p, const char *name, unsigned int id,
	     enum debug_type_kind kind)
{
  struct pr_handle *info = (struct pr_handle *) p;
  const char *t, *tag;
  char idbuf[22];

#if 0
  switch (kind)
    {
    case DEBUG_KIND_STRUCT:
      t = "struct ";
      break;
    case DEBUG_KIND_UNION:
      t = "union ";
      break;
    case DEBUG_KIND_ENUM:
      t = "enum ";
      break;
    case DEBUG_KIND_CLASS:
      t = "class ";
      break;
    case DEBUG_KIND_UNION_CLASS:
      t = "union class ";
      break;
    default:
      /* PR 25625: Corrupt input can trigger this case.  */
      return false;
    }

  if (! push_type (info, t))
    return false;
  if (name != NULL)
    tag = name;
  else
    {
      sprintf (idbuf, "__anon_struct_%u", id);
      tag = idbuf;
    }

  if (! append_type (info, tag))
    return false;
  if (name != NULL && kind != DEBUG_KIND_ENUM)
    {
      sprintf (idbuf, " /* id %u */", id);
      if (! append_type (info, idbuf))
	return false;
    }
#endif
  if (! push_type (info, "{\"info_type\" : \"tag_type\""))
    return false;
  switch (kind)
    {
    case DEBUG_KIND_STRUCT:
      t = "struct";
      break;
    case DEBUG_KIND_UNION:
      t = "union";
      break;
    case DEBUG_KIND_ENUM:
      t = "enum";
      break;
    case DEBUG_KIND_CLASS:
      t = "class";
      break;
    case DEBUG_KIND_UNION_CLASS:
      t = "union class";
      break;
    default:
      /* PR 25625: Corrupt input can trigger this case.  */
      return false;
    }

  if (! append_type (info, ", \"kind\" : \""))
    return false;
  if (! append_type (info, t))
    return false;
  if (! append_type (info, "\""))
    return false;

#if 0
  if (name != NULL)
    tag = name;
  else
    {
      sprintf (idbuf, "__anon_struct_%u", id);
      tag = idbuf;
    }

  if (! append_type (info, ", \"name\" : \""))
    return false;
  if (! append_type (info, tag))
    return false;
  if (! append_type (info, "\""))
    return false;
#endif
  if (name != NULL)
  {
    if (! append_type (info, ", \"name\" : \""))
      return false;
    if (! append_type (info, name))
      return false;
    if (! append_type (info, "\""))
      return false;
  }

#if 0
  if (name != NULL && kind != DEBUG_KIND_ENUM)
#endif
    {
      sprintf (idbuf, ", \"id\" : %u", id);
      if (! append_type (info, idbuf))
  return false;
    }

  if (! append_type (info, "}"))
    return false;

  return true;
}

/* Output a typedef.  */

static bool
pr_typdef (void *p, const char *name)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *s;

#if 0
  if (! substitute_type (info, name))
    return false;
#endif

  s = pop_type (info);
  if (s == NULL)
    return false;

#if 0
  indent (info);
  fprintf (info->f, "typedef %s;\n", s);
#endif
  fprintf (info->f, "{\"info_type\" : \"typdef\", \"type\" : %s, \"name\" : \"%s\"},\n", s, name);

  free (s);

  return true;
}

/* Output a tag.  The tag should already be in the string on the
   stack, so all we have to do here is print it out.  */

static bool
pr_tag (void *p, const char *name ATTRIBUTE_UNUSED)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *t;

  t = pop_type (info);
  if (t == NULL)
    return false;

#if 0
  indent (info);
  fprintf (info->f, "%s;\n", t);
#endif
  fprintf (info->f, "{\"info_type\" : \"tag\", \"type\" : %s},\n", t);

  free (t);

  return true;
}

/* Output an integer constant.  */

static bool
pr_int_constant (void *p, const char *name, bfd_vma val)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char ab[22];

  indent (info);
  print_vma (val, ab, false, false);
#if 0
  fprintf (info->f, "const int %s = %s;\n", name, ab);
#endif
  fprintf (info->f, "{\"info_type\" : \"int_constant\", \"name\" : \"%s\", \"ab\" : %s},\n", name, ab);
  return true;
}

/* Output a floating point constant.  */

static bool
pr_float_constant (void *p, const char *name, double val)
{
  struct pr_handle *info = (struct pr_handle *) p;

#if 0
  indent (info);
  fprintf (info->f, "const double %s = %g;\n", name, val);
#endif
  fprintf (info->f, "{\"info_type\" : \"float_constant\", \"name\" : \"%s\", \"val\" : %g},\n", name, val);
  return true;
}

/* Output a typed constant.  */

static bool
pr_typed_constant (void *p, const char *name, bfd_vma val)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *t;
  char ab[22];

  t = pop_type (info);
  if (t == NULL)
    return false;

#if 0
  indent (info);
#endif
  print_vma (val, ab, false, false);
#if 0
  fprintf (info->f, "const %s %s = %s;\n", t, name, ab);
#endif
  fprintf (info->f, "{\"info_type\" : \"typed_constant\", \"type\" : %s, \"name\" : \"%s\", \"ab\" : %s},\n", t, name, ab);

  free (t);

  return true;
}

/* Output a variable.  */

static bool
pr_variable (void *p, const char *name, enum debug_var_kind kind,
	     bfd_vma val)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *t;
  char ab[22];

#if 0
  if (! substitute_type (info, name))
    return false;
#endif

  t = pop_type (info);
  if (t == NULL)
    return false;

  bool is_static = false;
  bool is_register = false;

#if 0
#if SHOULD_DUMP_VARIABLES
  indent (info);
  switch (kind)
    {
    case DEBUG_STATIC:
    case DEBUG_LOCAL_STATIC:
      fprintf (info->f, "static ");
      break;
    case DEBUG_REGISTER:
      fprintf (info->f, "register ");
      break;
    default:
      break;
    }
  print_vma (val, ab, true, true);
  fprintf (info->f, "%s /* %s */;\n", t, ab);
#endif
#endif
  switch (kind)
    {
    case DEBUG_STATIC:
    case DEBUG_LOCAL_STATIC:
      is_static = true;
      break;
    case DEBUG_REGISTER:
      is_register = true;
      break;
    default:
      break;
    }
  print_vma (val, ab, true, true);
  fprintf (info->f, "{\"info_type\" : \"variable\", \"type\" : %s, \"name\" : \"%s\", \"ab\" : %s, \"static\" : %s, \"register\" : %s},\n", t, name, ab, is_static ? "true" : "false", is_register ? "true" : "false");

  free (t);

  return true;
}

/* Start outputting a function.  */

static bool
pr_start_function (void *p, const char *name, bool global)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *t;

#if 0
  if (! substitute_type (info, name))
    return false;
#endif

  t = pop_type (info);
  if (t == NULL)
    return false;

#if 0
#if SHOULD_DUMP_FUNCTIONS
  indent (info);
  if (! global)
    fprintf (info->f, "static ");
  fprintf (info->f, "%s (", t);
#endif
#endif
  fprintf (info->f, "{\"info_type\" : \"start_function\", \"type\" : %s, \"name\" : \"%s\", \"global\" : %s, \"parameters\" : [", t, name, global ? "true" : "false");

  info->parameter = 1;

  return true;
}

/* Output a function parameter.  */

static bool
pr_function_parameter (void *p, const char *name,
		       enum debug_parm_kind kind, bfd_vma val)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char *t;
  char ab[22];

  bool is_pointer = false;

  if (kind == DEBUG_PARM_REFERENCE
      || kind == DEBUG_PARM_REF_REG)
    {
#if 0
      if (! pr_reference_type (p))
	return false;
#endif
      is_pointer = true;
    }

#if 0
  if (! substitute_type (info, name))
    return false;
#endif

  t = pop_type (info);
  if (t == NULL)
    return false;

  bool is_register = false;
  if (kind == DEBUG_PARM_REG || kind == DEBUG_PARM_REF_REG)
    is_register = true;

  if (info->parameter != 1)
    fprintf (info->f, ", ");
#if 0
#if SHOULD_DUMP_FUNCTIONS
  if (info->parameter != 1)
    fprintf (info->f, ", ");

  if (kind == DEBUG_PARM_REG || kind == DEBUG_PARM_REF_REG)
    fprintf (info->f, "register ");
#endif
#endif

  print_vma (val, ab, true, true);
#if 0
#if SHOULD_DUMP_FUNCTIONS
  fprintf (info->f, "%s /* FUNCARG: %s */", t, ab);
#else
#if SHOULD_DUMP_FUNCARGS
  fprintf (info->f, "%s; /* FUNCARG: %s */\n", t, ab);
#endif
#endif
#endif

  fprintf (info->f, "{\"info_type\" : \"function_parameter\", \"type\" : %s, \"name\" : \"%s\", \"pointer\" : %s, \"register\" : %s, \"ab\" : %s}", t, name, is_pointer ? "true" : "false", is_register ? "true" : "false", ab);

  free (t);

  ++info->parameter;

  return true;
}

/* Start writing out a block.  */

static bfd_vma cur_start_addr = 0;
static bfd_vma cur_end_addr = 0;

static bool
pr_start_block (void *p, bfd_vma addr)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char ab[22];

  print_vma (addr, ab, true, true);

  if (info->parameter > 0)
    {
#if 0
#if SHOULD_DUMP_FUNCTIONS
#if 0
      fprintf (info->f, ")\n");
#else
      fprintf (info->f, ");");
#endif
#endif
#endif
      fprintf (info->f, "], \"addr\" : %s},\n", ab);
      info->parameter = 0;
    }

#if 0
#if SHOULD_DUMP_FUNCTIONS
#if 0
  indent (info);
#endif
  print_vma (addr, ab, true, true);
  if (cur_start_addr == 0)
  {
    fprintf (info->f, " /* FUNC AT: %s */\n", ab);
    cur_start_addr = addr;
  }
#if 0
  fprintf (info->f, "{ /* %s */\n", ab);
#endif
#endif

#if 0
  info->indent += 2;
#endif
#endif

  fprintf (info->f, "{\"info_type\" : \"start_block\", \"ab\" : %s},\n", ab);

  return true;
}

/* Write out line number information.  */

static bool
pr_lineno (void *p, const char *filename, unsigned long lineno, bfd_vma addr)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char ab[22];

#if 0
  indent (info);
#endif
  print_vma (addr, ab, true, true);
#if 0
  fprintf (info->f, "/* file %s line %lu addr %s */\n", filename, lineno, ab);
#endif
  fprintf (info->f, "{\"info_type\" : \"lineno\", \"filename\" : \"%s\", \"lineno\" : %lu, \"ab\" : %s},\n", filename, lineno, ab);

  return true;
}

/* Finish writing out a block.  */

static bool
pr_end_block (void *p, bfd_vma addr)
{
  struct pr_handle *info = (struct pr_handle *) p;
  char ab[22];

#if 0
  info->indent -= 2;

  indent (info);
#endif
  print_vma (addr, ab, true, true);

  cur_end_addr = addr;
#if 0
  fprintf (info->f, "} /* %s */\n", ab);
#endif
  fprintf (info->f, "{\"info_type\" : \"end_block\", \"ab\" : %s},\n", ab);

  return true;
}

/* Finish writing out a function.  */

static bool
pr_end_function (void *p)
{
  struct pr_handle *info = (struct pr_handle *) p;
  cur_start_addr = 0;
  cur_end_addr = 0;
#if 0
  fprintf (info->f, "\n");
#endif
  fprintf (info->f, "{\"info_type\" : \"end_function\"},\n");
  return true;
}

