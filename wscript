import Options
import sys

srcdir = "."
blddir = "build"
VERSION = "0.0.1"

def set_options(opt):
  opt.tool_options('compiler_cxx')
  opt.tool_options('misc')
  opt.add_option('--without-ecdsa'
                 , action='store'
                 , default=False
                 , help='Skip over ECDSA bindings'
                 , dest='without_ecdsa')
                

def configure(conf):
  conf.check_tool("compiler_cxx")
  conf.check_tool("node_addon")
  o = Options.options
  if Options.options.without_ecdsa:
    print 'without ecdsa'
    conf.env["WITHOUT_ECDSA"] = True
    conf.env.append_value("CXXFLAGS", "-DWITH_ECDSA=0")

def build(bld):
  obj = bld.new_task_gen("cxx", "shlib", "node_addon")
  obj.target = 'dcrypt'
  #obj.source = bld.glob('src/*.cc')
  obj.find_sources_in_dirs("src")
  if Options.options.without_ecdsa:
    print 'building without ECDSA bindings'
  if bld.env["WITHOUT_ECDSA"]:
    print 'building without ecdsa 2'
  
