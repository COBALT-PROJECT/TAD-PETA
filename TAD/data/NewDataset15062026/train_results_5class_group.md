# New-dataset model — taxonomy=5class, split=group

- packets: 911619
- classes: [np.str_('benign'), np.str_('hydra_bruteforce'), np.str_('nmap_scan'), np.str_('post_exploitation'), np.str_('stress_test')]
- class counts: {np.str_('benign'): 829915, np.str_('hydra_bruteforce'): 36469, np.str_('nmap_scan'): 1680, np.str_('post_exploitation'): 874, np.str_('stress_test'): 42681}

- split: group  (train 793116 / test 118503)

==================================================================
  Random Forest
==================================================================
                   precision    recall  f1-score   support

           benign     0.9963    0.9921    0.9942    103888
 hydra_bruteforce     0.8856    0.9798    0.9303      7616
        nmap_scan     0.9855    0.8358    0.9045       408
post_exploitation     0.1818    0.0159    0.0293       251
      stress_test     0.9973    0.9842    0.9907      6340

         accuracy                         0.9883    118503
        macro avg     0.8093    0.7616    0.7698    118503
     weighted avg     0.9875    0.9883    0.9876    118503

  overall accuracy   : 0.9883
  balanced accuracy  : 0.7616   (macro-avg recall)
  macro F1 (test)    : 0.7698
  macro F1 (train)   : 1.0000   [train-test gap = +0.2302]

  Confusion matrix (rows=true, cols=pred):
         benign  hydra_brut   nmap_scan  post_explo  stress_tes
    benign             103071         790           5          12          10
    hydra_brutefor        148        7462           0           6           0
    nmap_scan              49          11         341           0           7
    post_exploitat        100         147           0           4           0
    stress_test            84          16           0           0        6240

==================================================================
  Hist Gradient Boosting
==================================================================
                   precision    recall  f1-score   support

           benign     0.9984    0.9867    0.9925    103888
 hydra_bruteforce     0.8553    0.9873    0.9166      7616
        nmap_scan     0.9478    0.9338    0.9407       408
post_exploitation     0.2584    0.3068    0.2805       251
      stress_test     0.9866    0.9877    0.9872      6340

         accuracy                         0.9851    118503
        macro avg     0.8093    0.8404    0.8235    118503
     weighted avg     0.9869    0.9851    0.9857    118503

  overall accuracy   : 0.9851
  balanced accuracy  : 0.8404   (macro-avg recall)
  macro F1 (test)    : 0.8235
  macro F1 (train)   : 0.8948   [train-test gap = +0.0714]

  Confusion matrix (rows=true, cols=pred):
         benign  hydra_brut   nmap_scan  post_explo  stress_tes
    benign             102503        1101          20         193          71
    hydra_brutefor         65        7519           1          25           6
    nmap_scan               7          12         381           0           8
    post_exploitat         32         142           0          77           0
    stress_test            58          17           0           3        6262

**Best: Hist Gradient Boosting — macro-F1=0.8235, balanced-acc=0.8404, acc=0.9851**
Artifact: `models/multiclass/hgb_newdataset_5class.joblib`