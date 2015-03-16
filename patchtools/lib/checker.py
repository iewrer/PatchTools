# -*- coding: UTF-8 -*-
'''
Created on Feb 20, 2014

@copyright 2014, Milton C Mobley

See the checker module section of the documentation for further information.
'''
import sys

from symbol import if_stmt
from __builtin__ import file
'''
ongoing:change to store the patch's line number of old version,maps to patch's line number of new version 
'''

# 2to3 from types import str

from patchtools.lib.patch      import Patch
from patchtools.lib.ptobject   import PTObject
from patchtools.lib.exceptions import PT_ParameterError
from patchtools.lib.functions  import Functions as ut

#++
class Checker(PTObject):
    """ Validate the contents of Linux kernel patch files against
        the files specified in them
    """
    #--
     
    #++
    def __init__(self, params):
        """ Constructor
        changed version by barry           
        Args:
            params (dict): parameters
                sourcedir  (string,required):       path to source directory
                patchdir   (string,required):       path to patch directory
                targets    (string/list, optional): target file(s)
                indent     (int, optional):         indentation
                    default = 3
                mode (string, optional): scanning mode
                    'full'     : report edit errors only
                    'complete' : report status of all edits
                    default is 'full' 
                find (bool, optional): find missing strings
                    default is True
                debug (int, optional) debug options
                    default is 0
            
        Raises:
            PT_ParameterError
                    
        Notes:
            If '' is passed as sourcedir or patchdir, the caller must supply file
            paths to the match method that are accessible from the caller's current dircectory.
                
            If 'targets' is specified the code will only scan diff sections that
            modify the filenames in params['targets]
        """
        #--
        
        self.name = 'Checker'
        
        if ((params is None) or (not isinstance(params, dict))):
            raise PT_ParameterError(self.name, 'params')
        
        self.sourcedir = self._check_required_string_param(params, 'sourcedir')
        self._check_path_param('sourcedir', self.sourcedir)
        
        self.patchdir = self._check_required_string_param(params, 'patchdir')
        self._check_path_param('patchdir', self.patchdir)
        
        self.indent = self._check_optional_string_param(params, 'indent', '   ')
        self.mode   = self._check_optional_string_param(params, 'mode', 'full')
        self.find   = self._check_optional_param(params, 'find', bool, False)
        self.debug  = self._check_optional_param(params, 'debug', int, 0)
        
        """
        用于存储旧行号到新行号的映射表
        add:考察待增加行是否在指定位置或其他位置已出现
        """
        self.oldToNew = []
        
        if (not self.mode in ('full', 'complete')):
            raise PT_ParameterError(self.name, 'mode')
        
        if ('targets' in params): 
            targets = params['targets']
            if (ut.is_string_type(targets)):
                self.targets = [targets]
            elif (isinstance(targets, list) and ut.is_string_type(targets[0])):
                self.targets = targets
            else:
                raise PT_ParameterError(self.name, 'targets')
        else:
            self.targets = None
              
    #++                                
    def match(self, param):
        """ Validate the contents of one or more Linux kernel patch files against a kernel

        Args:
            param (choice):
                (string): path to patch file
                (list): paths to patch files
                
        Returns:
            A list of strings describing the results of analysis

        Raises:
            PT_ParameterError
            PT_ParsingError
        """
        #--
        
        if (ut.is_string_type(param)):
            paths = [param]
        elif (isinstance(param, (list, tuple))):
            paths = param
        else:
            raise PT_ParameterError(self.name, param)
        
        self.msgs = []
        self._misc_msg('patchdir  = "%s":' % self.patchdir)
        self._misc_msg('sourcedir = "%s":' % self.sourcedir)
        
        passed = skipped = 0
        for path in paths:
            if (self.debug > 0):
                print("matching %s" % path)
            errors = self._check(path)
            if (errors == 0):
                passed += 1
            elif (errors < 0):
                skipped += 1
                
        self._misc_msg('\nSummary:')
        self._misc_msg('%d passed, %d skipped, %d tested' % (passed, skipped, len(paths)), 1)
    
        return self.msgs
          
    def _check(self, patchpath):
        
        self._misc_msg('\nPATCH: "%s"' % patchpath)   
        patchpath = ut.join_path(self.patchdir, patchpath)
#         print patchpath
        pdata = Patch(patchpath)
        if (len(pdata.diffs) == 0):
            self._info_msg('skipping empty/commented patch', 1)
            return 0
 
        if (pdata.patch_type == 'binary'):
            self._info_msg('skipping binary patch', 1)
            return -1
               
        errors = 0
        context = []
        logs = ""
        
        for diff in pdata.diffs:
            
#             print "a path :" + diff.a_path
#             print "old path :" + diff.old_path
#             print "new path :" + diff.new_path
            self._misc_msg('DIFF: "%s"' % diff.spec, 1)
            
            if (not self._check_paths(diff)):
                errors += 1
                continue
            
            if (diff.old_path == '/dev/null'): # Can't fail on adding lines to a new file
                continue
            
#             print "old file path :" + ut.join_path(self.sourcedir, diff.old_path)       
            old_lines = ut.read_strings(ut.join_path(self.sourcedir, diff.old_path))
               
            new_hunks = []
            new_diff = []
            
            for hunk in diff.hunks:
                self._misc_msg('HUNK: "%s"' % hunk.spec, 2)
                edits = hunk.edits
                start = hunk.old_start
                count = hunk.old_count
                tag   = 'old'    
                note = hunk.note
                if (not self._check_hunk_format(start, count, len(old_lines), tag)):
                    errors += 1
                    continue
#                 print "begin to change hunk edits"
#                 errors += self._check_hunk_edits(diff.old_path, edits, start, count, note, old_lines)
                #获取并加入新的hunk信息
                new_hunks.append(self._patch_hunk_edits(diff.old_path, edits, start, count, note, old_lines))   
#                 print "end for this hunk"
            #写入当前hunk
            new_diff.append(diff.spec + "\n")
#             for (new_edits,new_start,context_start,new_count,context_count) in new_hunks:
#                 new_diff.append("@@ " + str(new_start) + "," + str(context_count) + " " + str(context_start)  + "," + str(new_count) + "@@\n")
#                 for edit in new_edits:
#                     new_diff.append(edit + "\n")
#             
#             context.append("".join(new_diff))
            for (new_place, before_start, before_count, after_start, after_count, log) in new_hunks:
                new_diff.append("@@ -" + str(before_start) + "," + str(before_count) + " +" + str(after_start)  + "," + str(after_count) + "@@\n" )
                for (edit, new_line_current, new_line_edited) in new_place:
                    new_diff.append(edit + "\n")
                logs += log
            context.append("".join(new_diff))
#             print new_diff
        #将新的diffs信息写入文件
        f = file("new.patch","w")
#         print context
        f.write("".join(context))
        f.close()
            
        logfile = file("log.txt","w")    
        
        logfile.write("".join(logs))
        logfile.close()
        
        self._info_msg("%d patch errors" % errors, 1)
        
        return errors
    
    def _check_paths(self, diff):
        ''' Check that:
            (1) file named in diff spec exists (GIT format only)
            (2) file named in '---' line exists or is /dev/null
            (3) file named in '+++' line exists or is /dev/null
            (4) file to be created exists in new tree
            (5) file to be deleted does not exist in old tree
        '''
#         print "source dir :" + self.sourcedir
#         print "a path :" + diff.a_path
#         print "joint path :" + str(ut.is_file(ut.join_path(self.sourcedir, diff.a_path)))
        if (not ut.is_file(ut.join_path(self.sourcedir, diff.a_path))):
            self._error_msg('"a" file not found: %s' % diff.a_path, 2)
            return False
#         print "old path :" + diff.old_path
#         print "joint path :" + ut.join_path(self.sourcedir, diff.old_path)
        if (diff.old_path != '/dev/null'):
            if (not ut.is_file(ut.join_path(self.sourcedir, diff.old_path))):
                self._error_msg('"old" file not found: %s' % diff.old_path, 2)
                return False
        else:
            if (ut.is_file(ut.join_path(self.sourcedir, diff.new_path))):
                self._error_msg('"new" file found in old tree: %s' % diff.new_path, 2)
                return False
                
        if (diff.new_path != '/dev/null'):
            if (not ut.is_file(ut.join_path(self.sourcedir, diff.new_path))):
                self._error_msg('"new" file not found: %s' % diff.new_path, 2)
                return False
        else:
            if (not ut.is_file(ut.join_path(self.sourcedir, diff.old_path))):
                self._error_msg('"old" file not found in old tree: %s' % diff.old_path, 2)
                return False
                
        return True
    
    def _check_hunk_format(self, start, count, length, tag):
        """ Validate a hunk's start, count, etc., values against the target file.
            The values may be incorrect due to previous merge of other patches
            into the 'old' tree, or to failure to add lines spcified in other hunks
            or patches.
        """
        if ((start > 0) and (count > 0)): # path is a file
            # start is a 1-based index
            if ((start > length) or ((start + count) > length)):   
                self._error_msg("invalid %s start or count for file: start=%d, count=%d, length=%d" % \
                                (tag, start, count, length), 3)
                return False 
            
        return True
    
    def _check_hunk_note(self, note, linenum, alines, old_path):
        """ A hunk "note" (any text after the second '@@') appears to be a copy of
            the closest previous line with a character in column 0. This is often
            the start declaration of a previous or enclosing function, e.g. 'static int foo(...'.
            We may be able to locate a source fragment that has moved by finding the note.
            But we only search for lines that are likely to be unique in the file.
        """
        errors = []
        if (self._is_landmark(old_path, note)):
            matches = self._find_line(note, alines)
            for match in matches:
                errors += ['hunk note found at %d' % match]
                
        return errors
                              
    def _is_null_path(self, path):
        """ Determine if a path indicates a non existent file.
        """
        return (path == '/dev/null')
    
    """
    edits:该hunk的修改
    start:该hunk的old_start
    count:该hunk的old_count，即修改前的行数
    lines:new version的内容
    目标：修改该hunk的edits/start/count等信息，与lines中的数据进行对应
    """
    def _patch_hunk_edits(self, filepath, edits, start, count, note, lines):
        """ Check edits against the "a" file. Report errors when lines to be deleted
            or merged are missing, and when lines to be added are present. Note that
            patch lines and source lines may have the same text, but differ in leading
            whitespace. We strip and normalize the strings before testing them. 
            In 'find' mode, try to find missing lines.
        """
        errors = warnings = 0
        
        current = start
        
        #[修改类型，该行修改前新位置,该行修改后新位置]
        new_place = []
        
        mismatches = []
        
        
        log = ""
                
        #index:记录在当前hunk中是第几行edit
        for (index, edit1, edit2) in self._get_edits(edits):
            
            op, text1 = edit1[0], edit1[1:]
            norm1 = ut.normalize_string(text1)
            if (current < len(lines)):
                line  = lines[current - 1] # patch line numbers are 1-based
                norm3 = ut.normalize_string(line)    
            else:
                break
            #(edit1,edit2)表示变更(-,+)，即先减后加
            if (edit2 is not None): # change request
                text2 = edit2[1:]
                norm2 = ut.normalize_string(text2)
                log += " change edit:\n"
                if (norm2 == norm3): # Change already applied
                    self._ok_msg('"after"  line found at %d: "%s"' % (current, text2), 3)
                    #此时change已经被应用，该两条连续edit可以被删除
                    log += "  change is applied,delete this edit\n"
                elif (norm1 == norm3): # Change not yet applied
                    self._info_msg('"after"  line not found at %d: "%s"' % (current, text2), 3)
                    #此时change尚未被应用，该两条连续edit需要被添加进来
                    new_line_current = current
                    new_line_edited = current
                    new_place.append((edit1, new_line_current, -1))
                    new_place.append((edit2, -1, new_line_edited))
                    log += "  change is not applied,added to new_place\n"
                else:
                    self._error_msg('"before"  line not found at %d: "%s"' % (current, text1), 3)
                    #此时edit1的内容不在原位，找到new中修改前的位置
                    new_line_current = self._find_new_place(text1, lines, current, filepath)
                    #如果在new中能找到该行
                    log += "  change line is not in place,try to find it in new\n"
                    if (new_line_current != -1) :
                        #在new中修改后的位置为-1（被删除）
                        new_line_edited = current
                        #记录下该行edit的信息
                        new_place.append((edit1, new_line_current, -1))
                        new_place.append((edit2, -1, new_line_edited))
                        log += "   find it,added to new_place\n"
                    #若new中不存在该行，则删除之
                    else:
                        log += "   not found, delete this edit\n"
                        pass                     
                current += 1 # advance to next edit line
                    
            elif (op == '-'): # delete line
                # A line to be deleted by the patch should be at the specified location,
                # but may be elsewhere in the file. If self.find is True, we will look for it.
                # Doing so may return multiple matches.
                log += " - edit:\n"
                if (norm1 != norm3):
                    self._error_msg('"delete" line not found at %d: "%s"' % (current, text1), 3)
                    mismatches += [(index, '-')]
                    log += "  delete line is not in place,try to find it in new\n"
                    #找到new中修改前的位置
                    new_line_current = self._find_new_place(text1, lines, current, filepath)
                    if (filepath.find("ASTConverter") != -1):
                        log += "ASTConverter:\n"
                        print("ASTConverter:")
                        log += "delete line:" + text + " \n new place: " + str(new_line_current) + "\n"
                        print("delete line:" + text + " \n new place: " + str(new_line_current))
                    #如果在new中能找到该行
                    if (new_line_current != -1) :
                        #在new中修改后的位置为-1（被删除）
                        new_line_edited = -1
                        #记录下该行edit的信息
                        new_place.append((edit1, new_line_current, new_line_edited))
                        log += "   find it,add to new_place\n"
                    #若new中不存在该行，则删除之
                    else:
                        log += "   not found, delete this edit\n"
                        pass             
                else:
                    if (self.mode == 'complete'):
                        self._ok_msg('"delete" line found at %d: "%s"' % (current, text1), 3)
                    #若该行还在原处,添加该行edit的信息，不变即可
                    new_line_current = current
                    new_line_edited = -1
                    new_place.append((edit1, new_line_current, new_line_edited))
                    log += "  delete line is in place, add it to new_place\n"
                current += 1 # advance to next edit line
            
            elif (op == '+'): # insert line
                # A line to be inserted by the patch should not be at the specified location,
                # but may be elsewhere in the file. If self.find is True, we will look for
                # significant "add" lines below. Doing so may return multiple matches.
                log += " + edit:\n"
                if (norm1 == norm3):
                    self._error_msg('"add"    line found at %d: "%s"' % (current, text1), 3)
                    errors += 1
                    log += "  add line is already in place,delete this edit\n"
                    #new中该位置已有该行，该条edit可被删除
                else: 
                    if (self.mode == 'complete'):
                        self._info_msg('"add"    line not found at next line: "%s"' % text1, 3)
                    mismatches += [(index, '+')]
                    new_line_current = self._find_new_place(text1, lines, current, filepath)
                    log += "  try to find add line in new:\n"
                    #若new中已有被添加的行，则删除这条edit
#                     if (new_line_current != -1) :
#                         print("   add line is already in new,delete this edit")
#                         pass
                    #否则：
#                     else:
                    if (True):
                        #如果该行不是第一行edit
                        if (len(new_place)):
                            #取出上一条edit
                            (last_edit, last_current, last_edited) = new_place[-1]
                            last_op, last_text = last_edit[0], last_edit[1:]
#                             if (last_op == '+' or last_op == ' '):
                            new_line_edited = last_current + 1
                            new_line_current = -1
                        #否则，因为该行edit是+，且该行在new中并没有出现，所以可直接使用start作为修改后的新位置
                        else:
                            new_line_current = -1
                            new_line_edited = start
                        #添加该行edit
                        new_place.append((edit1, new_line_current, new_line_edited)) 
                        log += "   add line is not in new,find a new place for this edit,add to new_place\n"            
            else: # (op == ' '): # merge line
                # a line to be merged by the patch should be at the specified location,
                # but may be elsewhere in the file. If self.find is True, we will look for it.
                # Doing so may return multiple matches.
                log += " merge line:\n"
                if (norm1 != norm3):
                    self._warn_msg('"merge"  line not found at %d: "%s"' % (current, text1), 3)
                    warnings += 1
                    mismatches += [(index, ' ')]
                    log += "  merge line not in place,try to find it in new\n"
                    #找到new中修改前的位置
                    new_line_current = self._find_new_place(text1, lines, current, filepath)
                    #如果在new中能找到该行
                    if (new_line_current != -1) :
                        #在new中修改后的位置为相同位置
                        new_line_edited = new_line_current
                        #记录下该行edit的信息
                        new_place.append((edit1, new_line_current, new_line_edited))
                        log += "   find it,add to new_place\n"
                    #若new中不存在该行，则删除之
                    else:
                        log += "   not in new,delete this edit\n"
                        pass   
                elif (self.mode == 'complete'):
                    self._ok_msg('"merge"  line found at %d: "%s"' % (current, text1), 3)
                    #若该行还在原处,添加该行edit的信息，不变即可
                    new_line_current = current
                    new_line_edited = current
                    new_place.append((edit1, new_line_current, new_line_edited))
                    log += "  merge line in place, add it to new_place\n"
                current += 1 # advance to next edit line                                 
               
        #查找起始的修改前后新位置
        find_before = False
        find_after = False
        
        before_start = -1
        after_start = -1
        
        log += " find start's new place for this hunk,before and after edited\n"
        for (edit, before, after) in new_place:
            if (find_before == False and before != -1):
                before_start = before
                find_before = True
            if (find_after == False and after != -1):
                after_start = after
                find_after = True
            if (find_before and find_after):
                break
        
        #如果前后两条edit的修改前新位置之间还有中间部分，则将其添加进来作为merge lines
        last_before = 0
        last_after = 0
        log += " find some merge lines missed between two edits,add them\n"
        for i, (edit, before, after) in  enumerate(new_place):
            if (i != 0 and before - last_before > 1):
                add = before + 1
                #这里可能会add超过lines范围？
                while (add < last_before and add < len(lines)):
                    add_line = lines[add]
                    add_text = ut.normalize_string(add_line)
                    new_place.insert(add, (" " + add_text, add, add))
                    add += 1
                    log += "   add lines...\n"
            last_before = before
            last_after = after
        
        #查找结束的修改前后新位置
        find_before = False
        find_after = False
        
        before_end = -1
        after_end = -1
        log += " find end's new place for this hunk,before and after edited\n"
        for (edit, before, after) in new_place[::-1]:
            if (find_before == False and before != -1):
                before_end = before
                find_before = True
            if (find_after == False and after != -1):
                after_end = after
                find_after = True
            if (find_before and find_after):
                break            
       
        #计算修改前后的行数统计
        before_count = before_end - before_start + 1
        after_count = after_end - after_start + 1
        
        
        return (new_place, before_start, before_count, after_start, after_count, log)   
    
    def _find_new_place(self, text, lines, current, filepath):
        new_pos = -1
        if (text.strip() == 'bool'):
            pass
        if (self._is_landmark(filepath, text)):   
            matches = self._find_line(text, lines)
            if (len(matches) == 1):
                new_pos = matches[0] + 1
            elif (len(matches) > 1):
                min = sys.maxint
                #若有多个match，选择其中离current最近的
                now = -1
                for match in matches:
                    if (abs(match - current) < min):
                        min = abs(match - current)
                        now = match
                #记录找到的该行的新位置
                new_pos = now + 1             
        return new_pos
    def _change_hunk_edits(self, filepath, edits, start, count, note, lines):
        
        errors = warnings = 0
        current = start
        new_edits = []
        #-m,n中的m
        new_start = start
        context_start = start
        #+m,n中的n
        new_count = 0
        #-m,n中的n
        context_count = 0
        
        oldToNew = {}
        
        #index表示在edits中的下标
        for (index, edit1, edit2) in self._get_edits(edits):
            
            op, text1 = edit1[0], edit1[1:]
            norm1 = ut.normalize_string(text1)
            print "lines: " + str(len(lines)) + "," + str(current)
            print "index: " + str(len(edits)) + "," + str(index)
            if (current > len(lines)) :
                break
            line  = lines[current - 1] # patch line numbers are 1-based
            norm3 = ut.normalize_string(line)
            print "begin changing for edit now"    
            
            #(edit1,edit2)表示变更(-,+)，即先减后加
            if (edit2 is not None): # change request
                print "    (-,+)"
                text2 = edit2[1:]
                norm2 = ut.normalize_string(text2)
                if (norm2 == norm3): # Change already applied
                    self._ok_msg('"after"  line found at %d: "%s"' % (current, text2), 3)
                    oldToNew[current] = -1
                elif (norm1 == norm3): # Change not yet applied
                    self._info_msg('"after"  line not found at %d: "%s"' % (current, text2), 3)
                    oldToNew[current] = current
                    new_edits.append(edit1)
                    new_edits.append(edit2)
                    new_count += 2
                    context_count += 1
                else:
                    self._error_msg('"before"  line not found at %d: "%s"' % (current, text1), 3)
                    if (self._match2(filepath, edits, lines, index, current, oldToNew, new_edits, new_count, context_count)):
                        new_edits.append(edit2)
                        new_count += 1
                        context_count += 1
                current += 1 # advance to next edit line
                
                    
            elif (op == '-'): # delete line
                # A line to be deleted by the patch should be at the specified location,
                # but may be elsewhere in the file. If self.find is True, we will look for it.
                # Doing so may return multiple matches.
                print "    -"
                if (norm1 != norm3):
                    self._error_msg('"delete" line not found at %d: "%s"' % (current, text1), 3)
                    self._match2(filepath, edits, lines, index, current, oldToNew, new_edits, new_count, context_count)
                else:
                    if (self.mode == 'complete'):
                        self._ok_msg('"delete" line found at %d: "%s"' % (current, text1), 3)
                    oldToNew[current] = current
                    new_edits.append(edit1)
                    new_count += 1
                    context_count -= 1
                current += 1 # advance to next edit line
            
            elif (op == '+'): # insert line
                # A line to be inserted by the patch should not be at the specified location,
                # but may be elsewhere in the file. If self.find is True, we will look for
                # significant "add" lines below. Doing so may return multiple matches.
                print "    +"
                if (norm1 == norm3):
                    self._error_msg('"add"    line found at %d: "%s"' % (current, text1), 3)
                    oldToNew[current] = -1
                    errors += 1
                else: 
                    if (self.mode == 'complete'):
                        self._info_msg('"add"    line not found at next line: "%s"' % text1, 3)
                    #查找上家的新位置，并+1作为自己的新位置
                    
                    #current表示在lines中的位置，即实际的多少行
                    up = current - 1
                    #index表示在edits中的下标
                    up_index = index - 1
                    #查找上家的新位置
                    print "    looking for new up"
                    #如果当前已经是头了，则直接查找当前行的新位置
                    if (up <= 0):
                        self._match2(filepath, edits, lines, index, current, oldToNew, new_edits, new_count, context_count)
                    #如果还未到头，且
                    #上家尚未查找过新位置，或者上家的新位置没有找到（上家在新文件中已被删除）
                    #那么查找上家的新位置，或者查找上家的上家
                    elif (not (oldToNew.has_key(up)) or oldToNew[up] == -1):
                        #如果当前上家没找到新位置，则继续往上找
                        while (oldToNew.has_key(up) and oldToNew[up] == -1):
                            up = up - 1
                            up_index = up_index - 1
                        #查找当前上家的新位置，若没有，则继续往上找
                        print "    begin 2nd while"
                        while(up > 0 and up_index > 0):
                            edit_text = edits[up_index]
                            text = edit_text[1:]
                            print "text got"
                            if (text.strip() == 'bool'):
                                print "    pass"
                                pass
                            if (self._is_landmark(filepath, text)):   
                                matches = self._find_line(text, lines)
                                print "    find matched for edit in old"
                                if (matches):
                                    min = sys.maxint
                                    #若有多个match，选择其中离current最近的
                                    for match in matches:
                                        if (abs(match - current) < min):
                                            min = match - current
                                    #记录找到的该行的新位置
                                    oldToNew[up] = (min + current) + 1 
                                    print "    matched: " + str(up) + "," + str(up_index)
                                    break
                                else:
                                    print "    not matched: " + str(up) + "," + str(up_index)                   
                            up = up - 1
                            up_index = up_index - 1
                        #将找到的上家新位置+1，作为自己的新位置，并将当前行加入到new_edits中
                        if (not (oldToNew.has_key(up))):
                            errors += 1 
                        else:
                            oldToNew[current] = oldToNew[up] + 1
                            new_edits.append(edit1)
                            new_count += 1
                            context_count += 1
                    print "    finding out up: " +  str(up)
                current += 1
            else: # (op == ' '): # merge line
                # a line to be merged by the patch should be at the specified location,
                # but may be elsewhere in the file. If self.find is True, we will look for it.
                # Doing so may return multiple matches.
                print "    merge"
                if (norm1 != norm3):
                    self._match2(filepath, edits, lines, index, current, oldToNew, new_edits, new_count, context_count)                       
                elif (self.mode == 'complete'):
                    self._ok_msg('"merge"  line found at %d: "%s"' % (current, text1), 3)
                elif (norm1 == norm3):
                    oldToNew[current] = current
                    new_edits.append(edit1)
                    new_count += 1
                    context_count += 1
                current += 1 # advance to next edit line  
        #记录新的起始位置
        new_start = start
        while((oldToNew.has_key(new_start)) and oldToNew[new_start] == -1):
            new_start += 1
        #待修改
        for edit in edits:
            op, text = edit[0], edit[1:]
            if (op == ' '):
                context_start = new_start
                break
        
        return new_edits,new_start,context_start,new_count,context_count
    
    def _check_hunk_edits(self, filepath, edits, start, count, note, lines):
        """ Check edits against the "a" file. Report errors when lines to be deleted
            or merged are missing, and when lines to be added are present. Note that
            patch lines and source lines may have the same text, but differ in leading
            whitespace. We strip and normalize the strings before testing them. 
            In 'find' mode, try to find missing lines.
        """
        errors = warnings = 0
        current = start
        mismatches = []
        
        #index表示修改内容在该行中的index
        for (index, edit1, edit2) in self._get_edits(edits):
            
            op, text1 = edit1[0], edit1[1:]
            norm1 = ut.normalize_string(text1)
            line  = lines[current - 1] # patch line numbers are 1-based
            norm3 = ut.normalize_string(line)    
            
            #(edit1,edit2)表示变更(-,+)，即先减后加
            if (edit2 is not None): # change request
                text2 = edit2[1:]
                norm2 = ut.normalize_string(text2)
                if (norm2 == norm3): # Change already applied
                    self._ok_msg('"after"  line found at %d: "%s"' % (current, text2), 3)
                elif (norm1 == norm3): # Change not yet applied
                    self._info_msg('"after"  line not found at %d: "%s"' % (current, text2), 3)
                else:
                    self._error_msg('"before"  line not found at %d: "%s"' % (current, text1), 3)
                current += 1 # advance to next edit line
                    
            elif (op == '-'): # delete line
                # A line to be deleted by the patch should be at the specified location,
                # but may be elsewhere in the file. If self.find is True, we will look for it.
                # Doing so may return multiple matches.
                if (norm1 != norm3):
                    self._error_msg('"delete" line not found at %d: "%s"' % (current, text1), 3)
                    mismatches += [(index, '-')]
                else:
                    if (self.mode == 'complete'):
                        self._ok_msg('"delete" line found at %d: "%s"' % (current, text1), 3)
                current += 1 # advance to next edit line
            
            elif (op == '+'): # insert line
                # A line to be inserted by the patch should not be at the specified location,
                # but may be elsewhere in the file. If self.find is True, we will look for
                # significant "add" lines below. Doing so may return multiple matches.
                if (norm1 == norm3):
                    self._error_msg('"add"    line found at %d: "%s"' % (current, text1), 3)
                    errors += 1
                else: 
                    if (self.mode == 'complete'):
                        self._info_msg('"add"    line not found at next line: "%s"' % text1, 3)
                    mismatches += [(index, '+')]
                                 
            else: # (op == ' '): # merge line
                # a line to be merged by the patch should be at the specified location,
                # but may be elsewhere in the file. If self.find is True, we will look for it.
                # Doing so may return multiple matches.
                if (norm1 != norm3):
                    self._warn_msg('"merge"  line not found at %d: "%s"' % (current, text1), 3)
                    warnings += 1
                    mismatches += [(index, ' ')]
                elif (self.mode == 'complete'):
                    self._ok_msg('"merge"  line found at %d: "%s"' % (current, text1), 3)
                current += 1 # advance to next edit line                                 
        
        if ((len(mismatches) > 0) and self.find):   
            self._match(filepath, edits, lines, mismatches)
            return 1
        else:
            return 0
    
    def _match2(self, filepath, edits, strings, index, current, newLineNum, newEdits, new_count, context_count):
        edit_text = edits[index]
        text = edit_text[1:]
        if (text.strip() == 'bool'):
            pass
        if (self._is_landmark(filepath, text)):   
            matches = self._find_line(text, strings)
            if (matches):
                min = sys.maxint
                #若有多个match，选择其中离current最近的
                for match in matches:
                    if (abs(match - current) < abs(min)):
                        min = match - current
                #记录找到的该行的新位置
                newLineNum[current] = (min + current) + 1
                #若当前新位置-上家新位置>1，说明中间插入了新行，将这些新行插入到newEdits中
                if (newLineNum.has_key(current - 1) and abs(newLineNum[current - 1] - newLineNum[current]) > 1):
                    if (newLineNum[current - 1] > newLineNum[current]):
                        newAddBegin = newLineNum[current]
                        newAddEnd = newLineNum[current - 1]
                    else:
                        newAddBegin = newLineNum[current - 1]
                        newAddEnd = newLineNum[current]
                    newAdd = strings[newAddBegin - 1 : newAddEnd]
                    for add in newAdd:
                        newContext = ' ' + add
                        newEdits.append(newContext)
                        new_count += 1
                        context_count += 1
                #将该行加入到newEdits中
                newEdits.append(edit_text)
                #记录该行对行数的贡献
                new_count += 1
                context_count += 1
                return 1
            #没找到，新版中已删除，忽略之
            else:
                #该行已被删除，没有新位置
                newLineNum[current] = -1
                return 0                       
    
    def _match(self, filepath, edits, strings, mismatches):
        ''' (1) Try to find missing "delete" or "merge" lines
            (2) Try to find "add" lines
        '''
        for edit_ndx, edit_type in mismatches:
            edit_text = edits[edit_ndx]
            text = edit_text[1:]
            if (text.strip() == 'bool'):
                pass
            if (self._is_landmark(filepath, text)):   
                matches = self._find_line(text, strings)
                for match in matches:
                    if (edit_type == '+'):
                        self._find_msg('"add"    line found at %d: "%s"' %  (match + 1, text), 3)
                    elif (edit_type == '-'):
                        self._find_msg('"delete" line found at %d: "%s"' %  (match + 1, text), 3)
                    else:
                        self._find_msg('"merge"  line found at %d: "%s"' %  (match + 1, text), 3)
                    
        return None # for bkpt only 

    def _find_line(self, text, strings):
        ''' Try to find text in the source strings.
        
            Both text and strings are normalized to eliminate mismatches on varying whitespace.
            
            Source strings may contain items such as author name, etc. with unicode characters
            that can't be converted to ascii or latin-1, so we must not convert the strings to
            Python 2.x str objects.
        '''
        text = ut.normalize_string(text, True)
        matches = []
        for index in range(len(strings)):
            string = ut.normalize_string(strings[index], True)
            if (text == string):
                matches += [index]
        
        return matches
            
    def _split_edit(self, edit):
        """ Split an edit line into op ('+','-' or ' ') and text. Edit lines sometimes
            come in as empty strings or just ' '
        """
        length = len(edit)
        if (length > 1): 
            op, text = edit[0], edit[1:]
        elif (length > 0):
            op, text = edit[0], ''
        else:
            op, text = ' ', ''
        
        return op, text
    
    def _get_edits(self, edits):
        ''' edit lines can be '+' (add), '-' (delete), or ' ' (merge) edits. A '-' followed by
            a '+' is a change request. We use a generator to return the '-' and '+' edits of changes
            as a pair, since modifying the loop index in a for statement controlled by a range
            doesn't work.
        '''
        elen  = len(edits)
        index = 0
        while (index < elen):
            e1 = edits[index]
            if (e1.startswith('-')):
                if (index < (elen - 1)):
                    e2 = edits[index + 1]
                    if (e2.startswith('+')):
                        yield (index, e1, e2)
                        index += 1
            else:
                yield (index, e1, None)
            index += 1
                
    def _is_landmark(self, filepath, string):
        """ Determine if a string is a "landmark" string , i.e. one that is likely to be unique
            in the file, and thus may be easy to isolate if it is present. Searching for strings
            such as '};' could give a large number of extraneous matches. 
        """
    
        if ((len(string) == 0) or string.isspace()):
            return False
        else:
            words = ut.string_to_words(string)
        
        words2 = []
        for word in words:
            if ('_' in word):
                sylls = word.split('_')
                words2 += sylls
            else:
                words2 += [word]
        words = words2
        
        words2 = []
        for word in words:
            if ('-' in word):
                sylls = word.split('-')
                words2 += sylls
            else:
                words2 += [word]
        words = words2
        
        if (len(words) > 4):
            return True
        
        index = filepath.rfind('/') + 1
        filename = filepath[index:]
            
        if (filename.endswith('.c') or filename.endswith('.h')):
            return self._is_c_h_landmark(string, words)
       
        elif (filename.endswith('.S') or filename.endswith('.inc')):
            return self._is_S_landmark(string, words)
        
        elif (filename.endswith('.dts') or filename.endswith('.dtsi')):   
            return self._is_dts_landmark(string, words)
                
        elif (filename.startswith('Kconfig')):
            return self._is_Kconfig_landmark(string, words)
   
        elif (filename.startswith('Makefile')):
            return self._is_Makefile_landmark(string, words)
        
        return self._is_generic_landmark(string, words)
                      
    def _is_c_h_landmark(self, string, words):
        """ Determine if a string is a "landmark" string in a .c or .h file.
        """
        
        #if (self._is_c_h_S_comment(string)):
        #    return False
                
        word0 = words[0]
        
        if ((len(words) == 1) and (words[0] in ('/*','*/','}',')',');','bool'))):
            return False
            
        if (word0 in ('#ifdef', '#ifndef', '#include', 'void', 'const', 'static', 'extern', 'struct', 'union')):
            return True
        
        elif (word0.startswith('MACHINE_')):
            return True
        
        elif (word0.startswith('MODULE_')):
            return True
        
        elif (word0.startswith('module_')):
            return True
        
        elif (word0.startswith('DEFINE_')):
            return True
        
        elif (word0.startswith('DECLARE_')):
            return True
        
        else:
            for word in words:
                if ('(' in word): # start of argument list?
                    return True
                elif (')' in word): # end of argument list?
                    return True
                elif ('->' in word): # pointer dereference
                    return True
            return False
        
    def _is_S_landmark(self, string, words):
        """ Determine if a string is a "landmark" string in a .S (assembler) file.
        """
        
        #if (self._is_c_h_S_comment(string)):
        #    return False
        
        word0 = words[0]
        
        if (word0 in ('#ifdef', '#ifndef', '#include', '#if')):
            return True
        
        elif (word0 in ('.section' , '.size', '.align')):
            return True
        
        elif (word0.endswith(':')):  # label
            return True
        
        else:
            return False
                          
    def _is_dts_landmark(self, string, words):
        """ Determine if a string is a "landmark" string in a .dts or .dtsi file.
            Any line that is not blank or '};' is significant.
        """
        
        if (words[0] in ('};','>;','/*','*/')):
            return False
        
        if ('status =' in string):
            return False
        
        if ('#address-cells = <1>;' in string):
            return False
        
        if ('interrupt-parent = <&intc>;' in string):
            return False
        
        if ('#size-cells = <0>;' in string):
            return False
        
        if ('pinctrl-names = "default";' in string):
            return False
        
        return True
            
        
    def _is_Kconfig_landmark(self, string, words):
        """ Determine if a string is a "landmark" string in a Kconfig file.
        """
        
        #if (self._is_makefile_comment(string)):
        #    return False
        
        return (words[0] in ('config','select','depends','source','menu','choice'))
    
    def _is_Makefile_landmark(self, string, words):
        """ Determine if a string is a "landmark" string in a Makefile.
        """
        
        if (string.startswith('# -')):
            return False
        
        if ('CONFIG_' in string):
            return True
        
        for word in words:
            if (word.endswith(':')): # make target
                return True
            
        return False
    
    def _is_generic_landmark(self, string, words):
        
        # Any string that has > 5 words may be unique
        if (len(words) > 5):
            return True
            
        # Any string that has a word with > 12 chars may be unique
        for word in words:
            if (len(word) > 12):
                return True
        
        return False

    def _is_c_h_S_comment(self, string):
        
        string = string.strip()
        if (string.startswith('/*')):
            return True
        elif (string.endswith('*/')):
            return True
        elif (string.startswith('//')):
            return True
        else:
            return False
    
    def _is_makefile_comment(self, string):
        
        return string.lstrip().startswith('#')
                         
    def _normalize(self, string):
        ''' Strip leading and trailing whitespace, but not trailing '\n'.
            Replace all internal whitespace segments by a single space.
        '''
        string = string.replace('\t', ' ')
        string = string.lstrip(' ')
        while ('  ' in string):
            string = string.replace('  ', ' ')
            
        return string
    
    def _indent(self, string, level=0):
        
        return level * self.indent + string
    
    def _error_msg(self, string, level=0):
        ''' Format error message
        '''
        text = self._indent('ERROR: ' + string, level)
        self.msgs += [text]
        if (self.debug > 1):
            print(text)
            
    def _info_msg(self, string, level=0):
        ''' Format info message
        '''
        text = self._indent('INFO:  ' + string, level)
        self.msgs += [text]
        if (self.debug > 1):
            print(text)
            
    def _find_msg(self, string, level=0):
        ''' Format info message
        '''
        text = self._indent('FIND:  ' + string, level)
        self.msgs += [text]
        if (self.debug > 1):
            print(text)
            
    def _ok_msg(self, string, level=0):
        ''' Format complete mode message
        '''
        text = self._indent('-OK-:  ' + string, level)
        self.msgs += [text]
        if (self.debug > 1):
            print(text)
    
    def _warn_msg(self, string, level=0):
        ''' Format info message
        '''
        text = self._indent('WARN:  ' + string, level)
        self.msgs += [text]
        if (self.debug > 1):
            print(text)
                    
    def _misc_msg(self, string, level=0):
        ''' Format miscellaneous message
        '''
        text = self._indent(string, level)
        self.msgs += [text]
        if (self.debug > 1):
            print(text)
    
    def _check_targets(self, diff_file):
        
        if (self.targets is None):
            return True
        
        for target in self.targets:
            if (target in diff_file):
                return True
        
        return False
                

        
    
    
    