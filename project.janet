(declare-project
  :name "janet-totp"
  :url "https://github.com/sogaiu/janet-totp"
  :repo "git+https://github.com/sogaiu/janet-totp.git")

(declare-source
  :source @["janet-totp"])

(declare-binscript
  :main "gh-totp"
  :is-janet true)

