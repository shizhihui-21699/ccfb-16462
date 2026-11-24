require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "lib" << "test"
  t.pattern = "test/**/*_test.rb"
  t.warning = false
end

desc "Run the end-to-end attack demo against a throwaway database"
task :demo do
  ruby "-Ilib", "bin/demo"
end

task default: :test
