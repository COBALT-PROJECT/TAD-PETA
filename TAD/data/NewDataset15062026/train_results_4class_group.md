# New-dataset model — taxonomy=4class, split=group

- packets: 991404
- classes: [np.str_('benign'), np.str_('hydra_bruteforce'), np.str_('nmap_scan'), np.str_('stress_test')]
- class counts: {np.str_('benign'): 906652, np.str_('hydra_bruteforce'): 36469, np.str_('nmap_scan'): 2059, np.str_('stress_test'): 46224}

- split: group  (train 756674 / test 234730)
- class-weight: sqrt

==================================================================
  Hist Gradient Boosting
==================================================================
                  precision    recall  f1-score   support

          benign     0.9981    0.9958    0.9969    216534
hydra_bruteforce     0.8965    0.9595    0.9269      7960
       nmap_scan     0.9531    0.9355    0.9442       434
     stress_test     0.9951    0.9895    0.9923      9802

        accuracy                         0.9942    234730
       macro avg     0.9607    0.9701    0.9651    234730
    weighted avg     0.9944    0.9942    0.9943    234730

  overall accuracy   : 0.9942
  balanced accuracy  : 0.9701   (macro-avg recall)
  macro F1 (test)    : 0.9651
  macro F1 (train)   : 0.9944   [train-test gap = +0.0293]

  Confusion matrix (rows=true, cols=pred):
         benign  hydra_brut   nmap_scan  stress_tes
    benign             215623         854          12          45
    hydra_brutefor        315        7638           6           1
    nmap_scan              12          14         406           2
    stress_test            87          14           2        9699

**Best: Hist Gradient Boosting — macro-F1=0.9651, balanced-acc=0.9701, acc=0.9942**
Artifact: `models/multiclass/hgb_newdataset_4class.joblib`