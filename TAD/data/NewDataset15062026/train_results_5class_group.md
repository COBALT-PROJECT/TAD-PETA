# New-dataset model — taxonomy=5class, split=group

- packets: 911619
- classes: [np.str_('benign'), np.str_('hydra_bruteforce'), np.str_('nmap_scan'), np.str_('post_exploitation'), np.str_('stress_test')]
- class counts: {np.str_('benign'): 829915, np.str_('hydra_bruteforce'): 36469, np.str_('nmap_scan'): 1680, np.str_('post_exploitation'): 874, np.str_('stress_test'): 42681}

- split: group  (train 793116 / test 118503)
- class-weight: sqrt

==================================================================
  Hist Gradient Boosting
==================================================================
                   precision    recall  f1-score   support

           benign     0.9977    0.9888    0.9933    103888
 hydra_bruteforce     0.8691    0.9824    0.9223      7616
        nmap_scan     0.9715    0.9191    0.9446       408
post_exploitation     0.2996    0.2948    0.2972       251
      stress_test     0.9935    0.9864    0.9899      6340

         accuracy                         0.9866    118503
        macro avg     0.8263    0.8343    0.8295    118503
     weighted avg     0.9876    0.9866    0.9869    118503

  overall accuracy   : 0.9866
  balanced accuracy  : 0.8343   (macro-avg recall)
  macro F1 (test)    : 0.8295
  macro F1 (train)   : 0.9192   [train-test gap = +0.0897]

  Confusion matrix (rows=true, cols=pred):
         benign  hydra_brut   nmap_scan  post_explo  stress_tes
    benign             102729         963          11         153          32
    hydra_brutefor        114        7482           0          19           1
    nmap_scan              14          11         375           0           8
    post_exploitat         38         139           0          74           0
    stress_test            71          14           0           1        6254

**Best: Hist Gradient Boosting — macro-F1=0.8295, balanced-acc=0.8343, acc=0.9866**
Artifact: `models/multiclass/hgb_newdataset_5class.joblib`