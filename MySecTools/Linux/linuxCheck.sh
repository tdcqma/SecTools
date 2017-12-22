#! /bin/bash
cat <<EOF
*************************************************************************
linux安全配置扫描脚本:
1. 输出结果也可以在当前目录的out.txt中查看
2. 检查范围：
 -》账号策略检查
 -》账号注销检查
 -》GRUB密码检查
 -》LILO密码检查
 -》UID为0的异常用户检查
*************************************************************************
EOF
rm -rf ./out.txt
echo -e "\n"
echo "[1] 账号策略检查中..."
passmax=`cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}'`
passmin=`cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^# | awk '{print $2}'`
passlen=`cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}'`
passage=`cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^# | awk '{print $2}'`
if [ $passmax -le 90 -a $passmax -gt 0 ];then
echo " [OK]口令生存周期为${passmax}天，符合要求" >> out.txt
else
echo " [ X ] 口令生存周期为${passmax}天，不符合要求,建议设置不大于90天" >> out.txt
fi
if [ $passmin -ge 6 ];then
echo " [OK]口令更改最小时间间隔为${passmin}天，符合要求" >> out.txt
else
echo " [ X ] 口令更改最小时间间隔为${passmin}天，不符合要求，建议设置大于等于6天" >> out.txt
fi
if [ $passlen -ge 8 ];then
echo " [OK]口令最小长度为${passlen},符合要求" >> out.txt
else
echo " [ X ] 口令最小长度为${passlen},不符合要求，建议设置最小长度大于等于8" >> out.txt
fi
if [ $passage -ge 30 -a $passage -lt $passmax ];then
echo " [OK]口令过期警告时间天数为${passage},符合要求" >> out.txt
else
echo " [ X ] 口令过期警告时间天数为${passage},不符合要求，建议设置大于等于30并小于口令生存周期" >> out.txt
fi
echo "..."
echo 'check over'
echo -e "\n"
echo "[2] 账号注销检查中..."
TMOUT=`cat /etc/profile | grep TMOUT | awk -F[=] '{print $2}'`
if [ ! $TMOUT ];then
echo " [ X ] 账号超时不存在自动注销,不符合要求，建议设置小于600秒" >> out.txt
else
if [ $TMOUT -le 600 -a $TMOUT -ge 10 ] ; then
echo " [ √ ] 账号超时时间${TMOUT}秒,符合要求" >> out.txt
else
echo " [ X ] 账号超时时间$TMOUT秒,不符合要求，建议设置小于600秒" >> out.txt
fi
fi
echo "..."
echo 'check over'
echo -e "\n"
echo "[3] GRUB密码检查中..."
grup_pwd=`cat /etc/grub.conf | grep -v ^# | grep password 2> /dev/null`
if [ $? -eq 0 ];then
echo " [ √ ] 已设置grub密码,符合要求" >> out.txt
else
echo " [ X ] 没有设置grub密码，不符合要求,建议设置grub密码" >> out.txt
fi
echo "..."
echo "check over"
echo -e "\n"
echo "[4] LILO密码检查中..."
if [ ! -f /etc/lilo.conf ] ; then
echo " [ √ ] lilo.conf配置文件不存在，系统可能不是通过LILO引导" >> out.txt
else
lilo_pwd=`cat /etc/lilo.conf | grep -v ^# | grep password &> /dev/null`
if [ $? -eq 0 ];then
echo " [ √ ] 已设置lilo密码,符合要求" >> out.txt
else
echo " [ X ] 没有设置lilo密码，不符合要求,建议设置lilo密码(操作有风险，需慎重!)" >> out.txt
fi
fi
echo "..."
echo "check over"
echo -e "\n"

echo "[5] 非root账号但UID为0的用户检查中..."
UIDS=`awk -F[:] 'NR!=1{print $3}' /etc/passwd`
flag=0
for i in $UIDS
do
  if [ $i = 0 ];then
     flag=1
  fi
done
  if [ $flag != 1 ];then
    echo " [ √ ] 不存在root账号外的UID为0的异常用户" >> out.txt
  else
    echo " [ X ] 存在非root但UID为0的异常用户，请立刻进行排查" >> out.txt
  fi
echo -e "\n"

echo "[6] /etc/profile中umask默认值检查中..."
umask1=`cat /etc/profile | grep umask | grep -v '^#' | awk '{print $2}'`
flags=0

for i in $umask1
do
  if [ $i = "027" ];then
    flags=1
  fi
done
if [ $flags = 1 ];then
  echo " [ √ ] /etc/profile文件中所设置的umask为${i},符合要求" >> out.txt
else
  echo " [ X ] /etc/profile文件中所设置的umask为${i},不符合要求" >> out.txt
  echo "      【理论上建议设置值为027,但因系统重要程度不同请根据具体情况慎重操作,如不确定请暂忽略此项】" >> out.txt
fi
echo -e "\n"


echo "[7] /etc/csh.cshrc中umask默认值检查中..."
umask2=`cat /etc/csh.cshrc | grep umask | grep -v '^#' | awk '{print $2}'`
flags=0

for i in $umask2
do
  if [ $i = "027" ];then
    flags=1
  fi
done
if [ $flags = 1 ];then
  echo " [ √ ] /etc/csh.cshrc文件中所设置的umask为${i},符合要求" >> out.txt
else
  echo " [ X ] /etc/csh.cshrc文件中所设置的umask为${i},不符合要求" >> out.txt
  echo "      【理论上建议设置值为027,但因系统重要程度不同请根据具体情况慎重操作,如不确定请暂忽略此项】" >> out.txt
fi
echo -e "\n"

echo "[8] /etc/bashrc中umask默认值检查中..."
umask3=`cat /etc/bashrc | grep umask | grep -v '^    #' | awk '{print $2}'`
flags=0

for i in $umask3
do
  if [ $i = "027" ];then
    flags=1
  fi
done
if [ $flags = 1 ];then
  echo " [ √ ] /etc/bashrc文件中所设置的umask为${i},符合要求" >> out.txt
else
  echo " [ X ] /etc/bashrc文件中所设置的umask为${i},不符合要求" >> out.txt
  echo "      【理论上建议设置值为027,但因系统重要程度不同请根据具体情况慎重操作,如不确定请暂忽略此项】" >> out.txt
fi
echo -e "\n"

echo "[9] 重要文件权限检查中..."
file1=`ls -l /etc/passwd | awk '{print $1}'`
if [ $file1 = "-rw-r--r--." ];then
  echo " [ √ ] /etc/passwd文件权限为644，符合要求" >> out.txt
else
  echo " [ X ] /etc/passwd文件权限为[$file1.],不符合要求" >> out.txt
fi

file2=`ls -l /etc/shadow | awk '{print $1}'`
if [ $file2 = "-rw-r--r--." ] || [ $file2 = "----------." ];then
  echo " [ √ ] /etc/shadow文件权限为400或000，符合要求" >> out.txt
else
  echo " [ X ] /etc/shadow文件权限为${file2},不符合要求" >> out.txt
fi

file3=`ls -l /etc/group | awk '{print $1}'`
if [ $file3 = "-rw-r--r--." ];then
  echo " [ √ ] /etc/group文件权限为644，符合要求" >> out.txt
else
  echo " [ X ] /etc/group文件权限为$file3，不符合要求" >> out.txt
fi

file4=`ls -l /etc/securetty | awk '{print $1}'`
if [ $file4 = "-rw-------." ];then
  echo " [ √ ] /etc/security文件权限为600，符合要求" >> out.txt
else
  echo " [ X ] /etc/security文件权限不为600，不符合要求，建议设置权限为600" >> out.txt
fi

file5=`ls -l /etc/services | awk '{print $1}'`
if [ $file5 = "-rw-r--r--." ];then
  echo " [ √ ] /etc/services文件权限为644，符合要求" >> out.txt
else
  echo " [ X ] /etc/services文件权限不为644，不符合要求，建议设置权限为644" >> out.txt
fi

file6=`ls -l /etc/xinetd.conf | awk '{print $1}'`
if [ !-f $file6 ];then
  echo " [ √ ] /etc/xinetd.conf文件不存在,暂略此项" >> out.txt
else
  if [ $file6 = "-rw-------." ];then
    echo " [ √ ] /etc/xinetd.conf文件权限为600，符合要求" >> out.txt
  else
    echo " [ X ] /etc/xinetd.conf文件权限不为600，不符合要求，建议设置权限为600" >> out.txt
  fi
fi

file7=`ls -l /etc/grub.conf | awk '{print $1}'`
if [ $file7 = "-rw-------." ];then
  echo " [ √ ] /etc/grub.conf文件权限为600，符合要求" >> out.txt
else
  echo " [ X ] /etc/grub.conf文件权限为$file7，不符合要求，建议设置权限为600" >> out.txt
fi

file8=`ls -l /etc/lilo.conf | awk '{print $1}'`
if [ -f /etc/lilo.conf ];then
  if [ $file8 = "-rw-------" ];then
    echo " [ √ ] /etc/lilo.conf文件权限为600，符合要求" >> out.txt
  else
    echo " [ X ] /etc/lilo.conf文件权限不为600，不符合要求，建议设置权限为600" >> out.txt
  fi
else
  echo " [ √ ] /etc/lilo.conf文件不存在,暂略此项" >> out.txt
fi

echo -e "\n"
echo "[10] 内核文件dump配置检查中..."
cat /etc/security/limits.conf | grep -v ^# | grep core
if [ $? = 0 ];then
  #soft=`cat /etc/security/limits.conf| grep -V ^# | grep core | awk {print $2}`
  soft=`cat /etc/security/limits.conf| grep -v '^#' | awk '{print $2}'` &> /dev/null
  for i in $soft
  do
    if [ $i = "soft" ];then
      echo -e " [ √ ] 内核文件dump配置检查[*\tsoft\tcore\t0]已经设置" >> out.txt
    fi
    if [ $i = "hard" ];then
      echo -e " [ √ ] 内核文件dump配置检查[*\thard\tcore\t0]已经设置" >> out.txt 
    fi
  done
else
  echo -e " [ X ] 没有设置core，建议在/etc/security/limits.conf中添加[*\tsoft\tcore\t0]和[*\thard\tcore\t0]" >> out.txt
fi

echo "--------------------------------------------------------------------------"
echo ""
echo "扫描结果："
echo ""
cat ./out.txt
echo ""
echo "--------------------------------------------------------------------------"
echo ""
